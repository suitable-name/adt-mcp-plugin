package com.sap.adt.mcp.preferences;

import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

/** Parent page for the MCP relay settings. */
public class McpRelayPreferencePage extends PreferencePage implements IWorkbenchPreferencePage {
    @Override
    public void init(IWorkbench workbench) {
        noDefaultAndApplyButton();
    }

    @Override
    protected Control createContents(Composite parent) {
        Label text = new Label(parent, SWT.WRAP);
        text.setText("Settings for the SAP ADT relay connection. Use Permissions to limit what a relay may do in this Eclipse.");
        return text;
    }
}
