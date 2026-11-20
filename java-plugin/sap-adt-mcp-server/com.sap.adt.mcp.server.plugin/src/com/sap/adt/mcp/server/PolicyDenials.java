package com.sap.adt.mcp.server;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/** Lets the MCP view show which layer refused a call, without the bridge classes knowing about the view. */
public final class PolicyDenials {
    private static final List<Consumer<String>> LISTENERS = new CopyOnWriteArrayList<>();

    private PolicyDenials() {
    }

    /** The listener runs on the bridge worker thread and must hand off to the UI thread itself. */
    public static void addListener(Consumer<String> listener) {
        LISTENERS.add(listener);
    }

    public static void removeListener(Consumer<String> listener) {
        LISTENERS.remove(listener);
    }

    /** Also used for pairing and binding messages. Lines must never contain secrets. */
    public static void report(String line) {
        for (Consumer<String> listener : LISTENERS) {
            try {
                listener.accept(line);
            } catch (RuntimeException e) {
                // A broken view must never change a policy decision.
            }
        }
    }
}
