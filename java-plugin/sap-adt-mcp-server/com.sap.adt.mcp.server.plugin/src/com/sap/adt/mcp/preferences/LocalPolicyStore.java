package com.sap.adt.mcp.preferences;

import java.util.List;
import java.util.Set;

import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.preferences.ConfigurationScope;
import org.eclipse.core.runtime.preferences.DefaultScope;
import org.eclipse.core.runtime.preferences.IEclipsePreferences;
import org.eclipse.core.runtime.preferences.IScopeContext;
import org.eclipse.core.runtime.preferences.InstanceScope;
import org.osgi.service.prefs.BackingStoreException;

import com.sap.adt.mcp.Activator;
import com.sap.adt.mcp.server.LocalPolicy;

/**
 * Eclipse preference backend for this Eclipse's local permissions (see {@link PermissionsModel} for the rules).
 * An administrator can preset the values in {@code plugin_customization.ini} and set
 * {@code permissions.locked=true}.
 */
public final class LocalPolicyStore {
    private static final IScopeContext[] ADMIN_SCOPES = { ConfigurationScope.INSTANCE, DefaultScope.INSTANCE };

    private static final PermissionsModel MODEL = new PermissionsModel(new PermissionsModel.Backend() {
        @Override
        public String admin(String key) {
            return Platform.getPreferencesService().getString(Activator.PLUGIN_ID, key, null, ADMIN_SCOPES);
        }

        @Override
        public String user(String key) {
            return InstanceScope.INSTANCE.getNode(Activator.PLUGIN_ID).get(key, null);
        }

        @Override
        public void putUser(String key, String value) {
            node().put(key, value);
            flush();
        }

        @Override
        public void removeUser(String key) {
            node().remove(key);
            flush();
        }

        private IEclipsePreferences node() {
            return InstanceScope.INSTANCE.getNode(Activator.PLUGIN_ID);
        }

        private void flush() {
            try {
                node().flush();
            } catch (BackingStoreException e) {
                throw new IllegalStateException("The permissions could not be saved.", e);
            }
        }
    });

    private LocalPolicyStore() {
    }

    public static boolean locked() {
        return MODEL.locked();
    }

    public static LocalPolicy load() {
        return MODEL.load();
    }

    /** @throws IllegalStateException when locked or when the store cannot be written */
    public static void save(boolean readOnly, Set<String> allowedTools, List<String> patterns) {
        MODEL.save(readOnly, allowedTools, patterns);
    }

    /** Whether legacy unencrypted relay calls are answered, read on every call. */
    public static boolean allowUnencrypted() {
        return MODEL.allowUnencrypted();
    }

    /** @throws IllegalStateException when locked or when the store cannot be written */
    public static void saveAllowUnencrypted(boolean allowed) {
        MODEL.saveAllowUnencrypted(allowed);
    }

    public static void resetAllowUnencrypted() {
        MODEL.resetAllowUnencrypted();
    }

    public static void reset() {
        MODEL.reset();
    }

    /** The global permissions combined with one paired desktop's own, read on every call. */
    public static LocalPolicy effectiveFor(String keyFingerprint) {
        return MODEL.effectiveFor(keyFingerprint);
    }

    /** One desktop's own settings; unset values mean "same as global". */
    public static LocalPolicy loadDesktop(String keyFingerprint) {
        return MODEL.forDesktop(keyFingerprint).load();
    }

    /** @throws IllegalStateException when locked or when the store cannot be written */
    public static void saveDesktop(String keyFingerprint, boolean readOnly, Set<String> allowedTools,
            List<String> patterns) {
        MODEL.forDesktop(keyFingerprint).save(readOnly, allowedTools, patterns);
    }

    /** Back to "same as global" for one desktop. */
    public static void resetDesktop(String keyFingerprint) {
        MODEL.forDesktop(keyFingerprint).reset();
    }

    /** Drops a removed desktop's settings. A locked store keeps whatever the administrator set. */
    public static void forgetDesktop(String keyFingerprint) {
        try {
            MODEL.forDesktop(keyFingerprint).reset();
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Locked or malformed: nothing of the user's to remove.
        }
    }
}
