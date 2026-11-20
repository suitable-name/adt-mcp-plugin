//! smol runtime glue shared by the relay, the desktop client and the tests:
//! a multi-threaded executor and timeouts.
//!
//! Part of the shared library; it depends on no other module of this package.

use std::{fmt, future::Future, sync::Once, time::Duration};

use smol::{Executor, Task, Timer, future};

static EXECUTOR: Executor<'static> = Executor::new();

/// Spawn a task on the process-wide executor. Its worker threads (one per CPU)
/// start on first use. Dropping the returned [`Task`] cancels it; call
/// [`Task::detach`] to let it run on its own.
///
/// # Panics
/// Panics if the operating system refuses to start the executor threads.
pub fn spawn<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> Task<T> {
    static START: Once = Once::new();
    START.call_once(|| {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        for index in 0..threads {
            std::thread::Builder::new()
                .name(format!("smol-worker-{index}"))
                .spawn(|| smol::block_on(EXECUTOR.run(future::pending::<()>())))
                .expect("Could not start an async executor thread.");
        }
    });
    EXECUTOR.spawn(future)
}

/// The deadline of [`timeout`] passed before the future completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("The operation timed out.")
    }
}

impl std::error::Error for Elapsed {}

/// Run `future` for at most `limit`. The future is dropped when the limit passes.
///
/// # Errors
/// Returns [`Elapsed`] if `limit` passes first.
pub async fn timeout<T>(limit: Duration, future: impl Future<Output = T>) -> Result<T, Elapsed> {
    future::or(async { Ok(future.await) }, async {
        Timer::after(limit).await;
        Err(Elapsed)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_returns_the_value_or_elapsed() {
        smol::block_on(async {
            assert_eq!(timeout(Duration::from_secs(5), async { 7 }).await, Ok(7));
            let never = future::pending::<()>();
            assert_eq!(
                timeout(Duration::from_millis(10), never).await,
                Err(Elapsed)
            );
        });
    }

    #[test]
    fn spawned_tasks_run_on_the_shared_executor() {
        assert_eq!(smol::block_on(spawn(async { 21 * 2 })), 42);
    }
}
