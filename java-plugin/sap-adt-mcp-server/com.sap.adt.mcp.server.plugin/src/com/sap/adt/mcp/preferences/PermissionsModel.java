package com.sap.adt.mcp.preferences;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.sap.adt.mcp.server.LocalPolicy;

/**
 * The storage rules for this Eclipse's local permissions, free of Eclipse types so a standalone harness can test them.
 *
 * <p>The user's own values live in the instance scope ({@link Backend#user}). Administrator presets and the lock
 * come from {@link Backend#admin}. When {@code permissions.locked} is true the user's values are ignored and
 * nothing can be saved.</p>
 */
public final class PermissionsModel {
    public static final String KEY_READ_ONLY = "permissions.readOnly";
    /** A comma-separated list of tool names, or {@link #ALL_TOOLS}. */
    public static final String KEY_ALLOWED_TOOLS = "permissions.allowedTools";
    /** A comma-separated list of package patterns. Empty means no local package restriction. */
    public static final String KEY_PACKAGE_PATTERNS = "permissions.packagePatterns";
    public static final String KEY_LOCKED = "permissions.locked";
    public static final String ALL_TOOLS = "*";
    /**
     * Whether this Eclipse still answers legacy (unencrypted) {@code tools/list} and {@code tools/call} from the
     * relay. "true" (the default in this version) or "false". Lockable with {@link #KEY_LOCKED}.
     */
    public static final String KEY_ALLOW_UNENCRYPTED = "relay.allowUnencrypted";

    /** Where the values come from. A null result means the key is not set in that layer. */
    public interface Backend {
        /** Administrator presets (plugin_customization.ini and the configuration scope). */
        String admin(String key);

        /** The user's instance-scope values. */
        String user(String key);

        void putUser(String key, String value);

        void removeUser(String key);
    }

    /** Per-desktop keys are {@code permissions.desktop.<key fingerprint>.<setting>} (D4). */
    public static final String DESKTOP_PREFIX = "permissions.desktop.";

    private final Backend backend;
    private final String readOnlyKey;
    private final String toolsKey;
    private final String patternsKey;

    public PermissionsModel(Backend backend) {
        this(backend, KEY_READ_ONLY, KEY_ALLOWED_TOOLS, KEY_PACKAGE_PATTERNS);
    }

    private PermissionsModel(Backend backend, String readOnlyKey, String toolsKey, String patternsKey) {
        this.backend = backend;
        this.readOnlyKey = readOnlyKey;
        this.toolsKey = toolsKey;
        this.patternsKey = patternsKey;
    }

    /**
     * The same three settings for one paired desktop. Unset values mean "same as global": no read-only, all tools,
     * no patterns, so the desktop's policy adds no restriction of its own. The lock flag stays the global
     * {@link #KEY_LOCKED}.
     *
     * @param keyFingerprint the desktop's inner-key fingerprint, 64 lowercase hex characters
     * @throws IllegalArgumentException for anything else, so a value can never reshape a preference key
     */
    public PermissionsModel forDesktop(String keyFingerprint) {
        if (keyFingerprint == null || keyFingerprint.length() != 64
                || !keyFingerprint.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw new IllegalArgumentException("Invalid desktop key fingerprint.");
        }
        String prefix = DESKTOP_PREFIX + keyFingerprint + ".";
        return new PermissionsModel(backend, prefix + "readOnly", prefix + "allowedTools", prefix + "packagePatterns");
    }

    /**
     * The policy for a call from one desktop: the global permissions combined with the desktop's own. A malformed
     * fingerprint or unreadable values refuse everything.
     */
    public LocalPolicy effectiveFor(String keyFingerprint) {
        LocalPolicy global = load();
        try {
            return global.intersect(forDesktop(keyFingerprint).load());
        } catch (RuntimeException e) {
            return LocalPolicy.blocked(global.locked());
        }
    }

    public boolean locked() {
        return "true".equalsIgnoreCase(String.valueOf(backend.admin(KEY_LOCKED)).strip());
    }

    private String value(boolean locked, String key, String fallback) {
        String user = locked ? null : backend.user(key);
        if (user != null) return user;
        String admin = backend.admin(key);
        return admin != null ? admin : fallback;
    }

    /** Read on every call, so a change applies to the next request. Unreadable values refuse everything. */
    public LocalPolicy load() {
        boolean locked = false;
        try {
            locked = locked();
            boolean readOnly = "true".equalsIgnoreCase(value(locked, readOnlyKey, "false").strip());
            Set<String> tools = parseTools(value(locked, toolsKey, ALL_TOOLS));
            List<String> patterns = LocalPolicy.parsePatterns(value(locked, patternsKey, ""));
            return LocalPolicy.of(readOnly, tools, patterns, locked);
        } catch (RuntimeException e) {
            return LocalPolicy.blocked(locked);
        }
    }

    /**
     * Whether unencrypted relay calls are allowed, read on every call. Unset means true. When the permissions are
     * locked the value comes from the administrator layers only. Any value other than "true" or "false", or a
     * store that cannot be read, counts as false (fail closed).
     */
    public boolean allowUnencrypted() {
        try {
            String text = value(locked(), KEY_ALLOW_UNENCRYPTED, "true").strip();
            return "true".equalsIgnoreCase(text);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** @throws IllegalStateException when the administrator locked the permissions */
    public void saveAllowUnencrypted(boolean allowed) {
        if (locked()) throw new IllegalStateException("Locked by your administrator.");
        backend.putUser(KEY_ALLOW_UNENCRYPTED, Boolean.toString(allowed));
    }

    /** Removes the user's own value, so the default (allowed) or the administrator's preset applies. */
    public void resetAllowUnencrypted() {
        if (locked()) throw new IllegalStateException("Locked by your administrator.");
        backend.removeUser(KEY_ALLOW_UNENCRYPTED);
    }

    /** Null means all tools. */
    static Set<String> parseTools(String text) {
        String trimmed = text.strip();
        if (trimmed.equals(ALL_TOOLS)) return null;
        Set<String> names = new LinkedHashSet<>();
        for (String name : trimmed.split("[,;\\s]+")) {
            if (!name.isEmpty()) names.add(name);
        }
        return names;
    }

    /**
     * @param allowedTools tool names, or null for all
     * @throws IllegalStateException when the administrator locked the permissions
     * @throws IllegalArgumentException for an invalid pattern list
     */
    public void save(boolean readOnly, Set<String> allowedTools, List<String> patterns) {
        if (locked()) throw new IllegalStateException("Locked by your administrator.");
        LocalPolicy.of(readOnly, allowedTools, patterns, false); // validates before anything is written
        backend.putUser(readOnlyKey, Boolean.toString(readOnly));
        backend.putUser(toolsKey, allowedTools == null ? ALL_TOOLS : String.join(",", new TreeSet<>(allowedTools)));
        backend.putUser(patternsKey, String.join(",", patterns));
    }

    /** Removes the user's own values, so the defaults or the administrator's presets apply. */
    public void reset() {
        if (locked()) throw new IllegalStateException("Locked by your administrator.");
        backend.removeUser(readOnlyKey);
        backend.removeUser(toolsKey);
        backend.removeUser(patternsKey);
    }
}
