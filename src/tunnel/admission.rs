//! Pre-admission of one stream (`docs/plan-e2e-envelope.md` §2, "Pre-admission").
//!
//! The client announces each request in an `Admit` frame. The relay checks the envelope
//! against its policy and, if it passes, remembers it for [`ADMISSION_TTL`]. The `Request`
//! that follows must carry exactly that envelope. A refusal changes nothing here.

use std::{collections::VecDeque, time::Instant};

use crate::{
    policy::{self, ToolClass},
    tunnel_proto::{ADMISSION_TTL, Class, Envelope, RelayPolicy},
};

/// JSON-RPC code of a refusal, as `mcp.rs` uses for a policy denial.
pub(super) const DENIED: i32 = -32_001;
/// Admissions that may wait for their request at the same time.
const MAX_PENDING: usize = 8;

/// An admitted envelope that waits for its request.
struct Pending {
    envelope: Envelope,
    admitted: Instant,
    deadline: Instant,
}

/// The admissions of one stream: the last admitted `seq` and the envelopes still waiting.
#[derive(Default)]
pub(super) struct Admissions {
    last: u64,
    pending: VecDeque<Pending>,
}

const fn class_of(class: ToolClass) -> Class {
    match class {
        ToolClass::Read => Class::Read,
        ToolClass::Execute => Class::Execute,
        ToolClass::Write => Class::Write,
    }
}

impl Admissions {
    /// Checks `envelope` and, if it passes, stores it with its deadline.
    ///
    /// `seq` must be exactly one more than the last admitted one (the first is 1). For
    /// `tools/call` the class is recomputed from the shared tool table and the tool must be
    /// allowed by `policy`. Every other method is always admitted.
    ///
    /// # Errors
    /// A plain refusal message. The state is unchanged in that case.
    pub(super) fn admit(
        &mut self,
        envelope: &Envelope,
        policy: &RelayPolicy,
        now: Instant,
    ) -> Result<(), &'static str> {
        if self.pending.len() >= MAX_PENDING {
            return Err("Too many requests are waiting to be sent.");
        }
        if self.last.checked_add(1) != Some(envelope.seq) {
            return Err("The sequence number is out of order.");
        }
        if envelope.method == "tools/call" {
            let (Some(tool), Some(class)) = (envelope.tool.as_deref(), envelope.class) else {
                return Err("A tool call needs a tool and an action class.");
            };
            let Some(known) = policy::tool_class(tool) else {
                return Err("The relay does not know this tool.");
            };
            if class_of(known) != class {
                return Err("The action class does not match the tool.");
            }
            if !policy.allowed_tools.iter().any(|allowed| allowed == tool) {
                return Err("The current access policy does not allow this tool.");
            }
        }
        self.last = envelope.seq;
        self.pending.push_back(Pending {
            envelope: envelope.clone(),
            admitted: now,
            deadline: now + ADMISSION_TTL,
        });
        Ok(())
    }

    /// Consumes the oldest admission for the `request` that arrived and returns the time it
    /// was admitted.
    ///
    /// # Errors
    /// The reason the stream must be closed: no admission, an expired admission, or an
    /// envelope that differs from the admitted one.
    pub(super) fn take_request(
        &mut self,
        request: &Envelope,
        now: Instant,
    ) -> Result<Instant, &'static str> {
        let Some(front) = self.pending.front() else {
            return Err("A request was sent without admission.");
        };
        if front.deadline <= now {
            return Err("The admission expired before the request arrived.");
        }
        if front.envelope != *request {
            return Err("The request does not match its admission.");
        }
        let admitted = front.admitted;
        self.pending.pop_front();
        Ok(admitted)
    }

    /// Whether an admitted request did not arrive in time. The oldest admission has the
    /// earliest deadline.
    pub(super) fn expired(&self, now: Instant) -> bool {
        self.pending
            .front()
            .is_some_and(|front| front.deadline <= now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn policy(tools: &[&str]) -> RelayPolicy {
        RelayPolicy {
            allowed_tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            package_scopes: Vec::new(),
        }
    }

    fn call(seq: u64, tool: &str, class: Class) -> Envelope {
        Envelope::new(seq, "tools/call", Some((tool, class)))
    }

    #[test]
    fn sequence_numbers_start_at_one_and_increase_by_one() {
        let now = Instant::now();
        let mut admissions = Admissions::default();
        let allowed = policy(&[]);
        let ping = |seq| Envelope::new(seq, "ping", None);
        assert!(admissions.admit(&ping(2), &allowed, now).is_err());
        assert!(admissions.admit(&ping(0), &allowed, now).is_err());
        assert!(admissions.admit(&ping(1), &allowed, now).is_ok());
        assert!(admissions.admit(&ping(1), &allowed, now).is_err());
        assert!(admissions.admit(&ping(3), &allowed, now).is_err());
        assert!(admissions.admit(&ping(2), &allowed, now).is_ok());
    }

    #[test]
    fn class_is_recomputed_and_unknown_or_forbidden_tools_are_refused() {
        let now = Instant::now();
        let mut admissions = Admissions::default();
        let allowed = policy(&["sap_get_source"]);
        assert!(
            admissions
                .admit(&call(1, "sap_get_source", Class::Write), &allowed, now)
                .is_err()
        );
        assert!(
            admissions
                .admit(&call(1, "sap_unknown", Class::Read), &allowed, now)
                .is_err()
        );
        assert!(
            admissions
                .admit(&call(1, "sap_set_source", Class::Write), &allowed, now)
                .is_err()
        );
        assert!(
            admissions
                .admit(&call(1, "sap_get_source", Class::Read), &allowed, now)
                .is_ok()
        );
    }

    #[test]
    fn a_denial_changes_nothing() {
        let now = Instant::now();
        let mut admissions = Admissions::default();
        let allowed = policy(&["sap_get_source"]);
        assert!(
            admissions
                .admit(&call(1, "sap_set_source", Class::Write), &allowed, now)
                .is_err()
        );
        assert_eq!((admissions.last, admissions.pending.len()), (0, 0));
        // The same sequence number is still the next one.
        assert!(
            admissions
                .admit(&call(1, "sap_get_source", Class::Read), &allowed, now)
                .is_ok()
        );
        assert_eq!((admissions.last, admissions.pending.len()), (1, 1));
    }

    #[test]
    fn always_admitted_methods_need_no_tool() {
        let now = Instant::now();
        let mut admissions = Admissions::default();
        let nothing = policy(&[]);
        for (seq, method) in [
            (1, "initialize"),
            (2, "tools/list"),
            (3, "ping"),
            (4, "notifications/initialized"),
            (5, "pair/claim"),
        ] {
            assert!(
                admissions
                    .admit(&Envelope::new(seq, method, None), &nothing, now)
                    .is_ok(),
                "{method}"
            );
        }
    }

    #[test]
    fn the_request_must_carry_exactly_the_admitted_envelope() {
        let now = Instant::now();
        let allowed = policy(&["sap_get_source"]);
        let admitted = call(1, "sap_get_source", Class::Read);
        let mut admissions = Admissions::default();
        assert!(admissions.take_request(&admitted, now).is_err());
        admissions.admit(&admitted, &allowed, now).unwrap();
        for changed in [
            call(1, "sap_search_object", Class::Read),
            call(2, "sap_get_source", Class::Read),
            Envelope::new(1, "tools/list", None),
        ] {
            assert!(admissions.take_request(&changed, now).is_err());
        }
        assert_eq!(admissions.take_request(&admitted, now), Ok(now));
        // An admission is used once.
        assert!(admissions.take_request(&admitted, now).is_err());
    }

    #[test]
    fn an_admission_expires_after_its_time_to_live() {
        let now = Instant::now();
        let allowed = policy(&[]);
        let envelope = Envelope::new(1, "ping", None);
        let mut admissions = Admissions::default();
        assert!(!admissions.expired(now));
        admissions.admit(&envelope, &allowed, now).unwrap();
        assert!(!admissions.expired(now + ADMISSION_TTL.saturating_sub(Duration::from_millis(1))));
        assert!(admissions.expired(now + ADMISSION_TTL));
        assert!(
            admissions
                .take_request(&envelope, now + ADMISSION_TTL)
                .is_err()
        );
    }

    #[test]
    fn waiting_admissions_are_bounded() {
        let now = Instant::now();
        let allowed = policy(&[]);
        let mut admissions = Admissions::default();
        for seq in 1..=8 {
            admissions
                .admit(&Envelope::new(seq, "ping", None), &allowed, now)
                .unwrap();
        }
        assert!(
            admissions
                .admit(&Envelope::new(9, "ping", None), &allowed, now)
                .is_err()
        );
    }
}
