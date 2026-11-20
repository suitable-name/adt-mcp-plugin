package com.sap.adt.mcp.tools;

import java.util.Locale;
import java.util.Optional;

/** Action class of a tool: what it may do to the SAP system. Mirrors {@code class} in tools.json. */
public enum ToolClass {
    READ,
    EXECUTE,
    WRITE;

    /** Parses the lower-case name used in tools.json. */
    public static Optional<ToolClass> parse(String name) {
        if (name == null) {
            return Optional.empty();
        }
        for (ToolClass value : values()) {
            if (value.name().toLowerCase(Locale.ROOT).equals(name)) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }
}
