package com.sap.adt.mcp.server;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

import com.sap.adt.mcp.tools.ToolCatalog;
import com.sap.adt.mcp.tools.ToolClass;

/**
 * This Eclipse's own permissions. They can only restrict what the relay allows, never extend it.
 *
 * <p>The package patterns use the relay's syntax and limits. An empty pattern list means no local package
 * restriction. A non-empty list allows only package-aware tools, as the relay's own rules do.</p>
 */
public final class LocalPolicy {
    private static final LocalPolicy UNRESTRICTED = new LocalPolicy(false, null, List.of(), false);

    private final boolean readOnly;
    /** Null means every tool. */
    private final Set<String> allowedTools;
    /** For display. After {@link #intersect} this is the union of every layer's patterns. */
    private final List<String> packagePatterns;
    /** Non-empty pattern layers; a call's target must match one pattern in each. */
    private final List<List<String>> layers;
    private final RelayPackageScopes scopes;
    private final boolean locked;

    private LocalPolicy(boolean readOnly, Set<String> allowedTools, List<String> packagePatterns, boolean locked) {
        this(readOnly, allowedTools, locked,
                packagePatterns.isEmpty() ? List.<List<String>>of() : List.of(List.copyOf(packagePatterns)));
    }

    private LocalPolicy(boolean readOnly, Set<String> allowedTools, boolean locked, List<List<String>> layers) {
        this.readOnly = readOnly;
        this.allowedTools = allowedTools == null ? null : Set.copyOf(allowedTools);
        this.layers = List.copyOf(layers);
        List<String> flat = new ArrayList<>();
        for (List<String> layer : layers) {
            for (String pattern : layer) {
                if (!flat.contains(pattern)) flat.add(pattern);
            }
        }
        this.packagePatterns = List.copyOf(flat);
        this.scopes = layers.isEmpty() ? RelayPackageScopes.NONE : RelayPackageScopes.ofLayers(layers);
        this.locked = locked;
    }

    /**
     * The stricter of this policy and {@code other}: read-only if either is, only tools both enable, and a target
     * must match the patterns of both. A policy that cannot be read (see {@link #blocked}) stays blocked.
     */
    public LocalPolicy intersect(LocalPolicy other) {
        Set<String> tools;
        if (allowedTools == null) {
            tools = other.allowedTools;
        } else if (other.allowedTools == null) {
            tools = allowedTools;
        } else {
            tools = new TreeSet<>(allowedTools);
            tools.retainAll(other.allowedTools);
        }
        List<List<String>> both = new ArrayList<>(layers);
        both.addAll(other.layers);
        return new LocalPolicy(readOnly || other.readOnly, tools, locked || other.locked, both);
    }

    public static LocalPolicy unrestricted() {
        return UNRESTRICTED;
    }

    /**
     * @param allowedTools the enabled tool names, or null for all tools
     * @param packagePatterns normalised patterns (see {@link #parsePatterns}); empty for no restriction
     * @throws IllegalArgumentException if a pattern is invalid or there are too many
     */
    public static LocalPolicy of(boolean readOnly, Set<String> allowedTools, List<String> packagePatterns, boolean locked) {
        return new LocalPolicy(readOnly, allowedTools, packagePatterns, locked);
    }

    /** A policy that allows nothing. The store returns it when saved values cannot be read safely. */
    public static LocalPolicy blocked(boolean locked) {
        return new LocalPolicy(true, Set.of(), List.of(), locked);
    }

    /**
     * Splits on commas, semicolons and whitespace, upper-cases, validates, sorts and removes duplicates.
     *
     * @throws IllegalArgumentException with a user-readable message
     */
    public static List<String> parsePatterns(String text) {
        Set<String> unique = new TreeSet<>();
        for (String token : text.split("[,;\\s]+")) {
            if (token.isEmpty()) continue;
            String pattern = token.toUpperCase(Locale.ROOT);
            if (!RelayPackageScopes.validPattern(pattern)) {
                throw new IllegalArgumentException("Invalid SAP package pattern: " + token);
            }
            unique.add(pattern);
        }
        if (unique.size() > RelayPackageScopes.MAX_PATTERNS) {
            throw new IllegalArgumentException(
                    "At most " + RelayPackageScopes.MAX_PATTERNS + " package patterns are supported.");
        }
        return new ArrayList<>(unique);
    }

    public boolean readOnly() {
        return readOnly;
    }

    /** The enabled tool names, or null when every tool is allowed. */
    public Set<String> allowedTools() {
        return allowedTools;
    }

    public List<String> packagePatterns() {
        return packagePatterns;
    }

    public boolean locked() {
        return locked;
    }

    RelayPackageScopes scopes() {
        return scopes;
    }

    /** Null when this Eclipse allows the tool, otherwise the reason it refuses. */
    String refusal(ToolCatalog catalog, String tool) {
        ToolClass toolClass = catalog.classOf(tool).orElse(null);
        if (toolClass == null) return "the tool is unknown to this Eclipse";
        String own = refusalOf(catalog, tool, toolClass);
        if (own != null) return own;
        // A composite tool also runs its components, so each of them must be allowed too.
        for (String component : catalog.components(tool)) {
            ToolClass componentClass = catalog.classOf(component).orElse(null);
            if (componentClass == null) return "the tool is unknown to this Eclipse";
            if (refusalOf(catalog, component, componentClass) != null) {
                return "it needs " + component + ", which is not permitted";
            }
        }
        return null;
    }

    private String refusalOf(ToolCatalog catalog, String tool, ToolClass toolClass) {
        if (readOnly && toolClass != ToolClass.READ) return "this Eclipse allows read-only tools only";
        if (allowedTools != null && !allowedTools.contains(tool)) return "the tool is not enabled in the permissions";
        if (!layers.isEmpty() && !catalog.packageAware(tool)) {
            return "the tool cannot be limited to the local package patterns";
        }
        return null;
    }

    /** One line for the MCP view, for example "Local permissions: read-only, 3 package patterns". */
    public String summary() {
        List<String> parts = new ArrayList<>();
        if (readOnly) parts.add("read-only");
        if (allowedTools != null) parts.add(allowedTools.size() + (allowedTools.size() == 1 ? " tool" : " tools"));
        if (!packagePatterns.isEmpty()) {
            parts.add(packagePatterns.size() + (packagePatterns.size() == 1 ? " package pattern" : " package patterns"));
        }
        String text = "Local permissions: " + (parts.isEmpty() ? "no restrictions" : String.join(", ", parts));
        return locked ? text + " (locked by your administrator)" : text;
    }
}
