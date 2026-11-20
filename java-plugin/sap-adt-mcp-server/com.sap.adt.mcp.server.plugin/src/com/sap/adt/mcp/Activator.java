package com.sap.adt.mcp;

import org.eclipse.jface.resource.ImageDescriptor;
import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;

import com.sap.adt.mcp.preferences.LocalPolicyStore;
import com.sap.adt.mcp.server.LegacyCalls;
import com.sap.adt.mcp.server.LocalPolicySource;
import com.sap.adt.mcp.server.E2eServices;
import com.sap.adt.mcp.server.SecureBlobStorage;

/**
 * The activator class controls the plug-in life cycle.
 */
public class Activator extends AbstractUIPlugin {

    public static final String PLUGIN_ID = "com.sap.adt.mcp.server.plugin";

    private static Activator plugin;

    public Activator() {
    }

    @Override
    public void start(BundleContext context) throws Exception {
        super.start(context);
        plugin = this;
        // The relay bridge reads the local permissions through this indirection on every call.
        LocalPolicySource.install(LocalPolicyStore::load);
        LegacyCalls.install(LocalPolicyStore::allowUnencrypted);
        // E2eServices has no Eclipse types: the secure storage for the inner key and the pin list comes from here.
        E2eServices.useStorage(SecureBlobStorage::new);
        // The inner key and the pin store exist from start-up, so the paired-desktops lists and the permissions
        // page can read them. The stream handler and the pairing gate need a connected SAP session and relay
        // identity, so the MCP view registers them with E2eServices when it connects.
        try {
            E2eServices.innerKeys();
            E2eServices.pinStore();
        } catch (RuntimeException e) {
            getLog().log(new org.eclipse.core.runtime.Status(org.eclipse.core.runtime.IStatus.WARNING, PLUGIN_ID,
                    "Encrypted relay streams are unavailable: the inner key or pin store could not be opened."));
        }
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        plugin = null;
        super.stop(context);
    }

    public static Activator getDefault() {
        return plugin;
    }

    public static ImageDescriptor getImageDescriptor(String path) {
        return imageDescriptorFromPlugin(PLUGIN_ID, path);
    }
}
