package com.sap.adt.mcp.preferences;

import org.eclipse.core.runtime.preferences.AbstractPreferenceInitializer;

import com.sap.adt.mcp.Activator;

/** Remembers the selected workspace project. SAP logon remains owned by ADT. */
public class PreferenceInitializer extends AbstractPreferenceInitializer {
    public static final String PREF_LAST_PROJECT = "sap.project.lastSelected";

    @Override
    public void initializeDefaultPreferences() {
        Activator.getDefault().getPreferenceStore().setDefault(PREF_LAST_PROJECT, "");
    }
}
