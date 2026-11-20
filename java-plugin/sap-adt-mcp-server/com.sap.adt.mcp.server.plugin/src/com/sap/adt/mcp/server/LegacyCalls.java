package com.sap.adt.mcp.server;

import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Where the legacy bridge path reads the "Allow unencrypted relay calls" setting, and where it reports refusals.
 * The plugin activator installs the preference reader at start-up, and the MCP view installs the refusal
 * listener. Like {@link LocalPolicySource}, this keeps the bridge classes free of Eclipse types. Until a reader
 * is installed, unencrypted calls are allowed (the default of this version).
 */
public final class LegacyCalls {
    /** The layer named in the log line for a refusal. */
    public static final String LAYER = "this Eclipse's encryption setting";

    private static volatile BooleanSupplier reader = () -> true;
    private static volatile Consumer<String> refusalListener = message -> { };

    private LegacyCalls() {
    }

    public static void install(BooleanSupplier allowUnencrypted) {
        reader = allowUnencrypted;
    }

    /** Receives one line per refused legacy call; pass null to remove. */
    public static void onRefusal(Consumer<String> listener) {
        refusalListener = listener == null ? message -> { } : listener;
    }

    public static boolean allowed() {
        return reader.getAsBoolean();
    }

    static void refused(String method) {
        refusalListener.accept("Refused an unencrypted " + method + " call. Denied by " + LAYER + ".");
    }
}
