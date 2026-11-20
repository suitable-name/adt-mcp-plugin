package com.sap.adt.mcp.server;

import java.util.function.Supplier;

/**
 * Where the production bridge reads this Eclipse's permissions. The plugin activator installs the preference
 * store reader at start-up. This indirection keeps the bridge classes free of Eclipse types, so the standalone
 * harnesses compile without Eclipse. Until a reader is installed everything is refused.
 */
public final class LocalPolicySource {
    private static volatile Supplier<LocalPolicy> reader = () -> LocalPolicy.blocked(false);

    private LocalPolicySource() {
    }

    public static void install(Supplier<LocalPolicy> policyReader) {
        reader = policyReader;
    }

    public static LocalPolicy current() {
        return reader.get();
    }
}
