package com.sap.adt.mcp.preferences;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import com.sap.adt.mcp.server.LocalPolicy;
import com.sap.adt.mcp.tools.ToolCatalog;

/**
 * Preferences → MCP Relay: the settings of this plugin that apply to every relay connection and every paired
 * desktop. Permissions of one paired desktop are set in the SAP ADT Relay view (its context menu), because they
 * belong to that pairing.
 */
public class McpRelayPreferencePage extends PreferencePage implements IWorkbenchPreferencePage {
    private Button readOnly;
    private Button allTools;
    private Table tools;
    private Text patterns;
    private Button allowUnencrypted;

    @Override
    public void init(IWorkbench workbench) {
        setDescription("Settings for every relay connection and every paired desktop of this Eclipse. "
                + "Permissions for a single paired desktop are in the SAP ADT Relay view: right-click the desktop.");
    }

    @Override
    protected Control createContents(Composite parent) {
        Composite page = new Composite(parent, SWT.NONE);
        GridLayout layout = new GridLayout(1, false);
        layout.marginWidth = 0;
        page.setLayout(layout);
        boolean locked = LocalPolicyStore.locked();
        if (locked) {
            Label notice = new Label(page, SWT.WRAP);
            notice.setText("Locked by your administrator. These values cannot be changed here.");
        }
        createPermissions(page, locked);
        createEncryption(page, locked);
        if (locked) noDefaultAndApplyButton();
        return page;
    }

    /** What any relay may do in this Eclipse, on top of the relay's own rules. */
    private void createPermissions(Composite page, boolean locked) {
        LocalPolicy current = LocalPolicyStore.load();
        Group group = new Group(page, SWT.NONE);
        group.setText("Permissions");
        group.setLayout(new GridLayout(1, false));
        group.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        wrapped(group, "Limits applied in this Eclipse in addition to the relay's own rules. They can only "
                + "restrict what the relay allows. Changes apply to the next call.");

        readOnly = new Button(group, SWT.CHECK);
        readOnly.setText("Read-only: allow only tools that read from SAP");
        readOnly.setSelection(current.readOnly());

        allTools = new Button(group, SWT.CHECK);
        allTools.setText("Allow all tools");
        allTools.setSelection(current.allowedTools() == null);
        allTools.addListener(SWT.Selection, event -> tools.setEnabled(!allTools.getSelection() && !locked));

        tools = new Table(group, SWT.BORDER | SWT.CHECK | SWT.V_SCROLL);
        GridData toolData = new GridData(SWT.FILL, SWT.FILL, true, true);
        toolData.heightHint = 140;
        tools.setLayoutData(toolData);
        for (String name : new TreeSet<>(ToolCatalog.bundled().names())) {
            TableItem item = new TableItem(tools, SWT.NONE);
            item.setText(name);
            item.setChecked(current.allowedTools() == null || current.allowedTools().contains(name));
        }
        tools.setEnabled(current.allowedTools() != null && !locked);

        wrapped(group, "Package patterns (comma or line separated, for example Z*, /NS/*). Empty means no local "
                + "package restriction. With patterns, only tools that work on a known package are allowed.");
        patterns = new Text(group, SWT.BORDER | SWT.MULTI | SWT.WRAP | SWT.V_SCROLL);
        GridData patternData = new GridData(SWT.FILL, SWT.FILL, true, false);
        patternData.heightHint = 50;
        patterns.setLayoutData(patternData);
        patterns.setText(String.join(", ", current.packagePatterns()));

        readOnly.setEnabled(!locked);
        allTools.setEnabled(!locked);
        patterns.setEditable(!locked);
    }

    /** Whether this Eclipse still answers unencrypted relay calls. */
    private void createEncryption(Composite page, boolean locked) {
        Group group = new Group(page, SWT.NONE);
        group.setText("Encryption");
        group.setLayout(new GridLayout(1, false));
        group.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));
        allowUnencrypted = new Button(group, SWT.CHECK);
        allowUnencrypted.setText("Allow unencrypted relay calls");
        allowUnencrypted.setSelection(LocalPolicyStore.allowUnencrypted());
        allowUnencrypted.setEnabled(!locked);
        wrapped(group, "When off, this Eclipse only answers end-to-end encrypted requests from paired desktops. "
                + "A compromised relay can then neither read nor send SAP calls.");
    }

    private static void wrapped(Composite parent, String text) {
        Label label = new Label(parent, SWT.WRAP);
        label.setText(text);
        GridData data = new GridData(SWT.FILL, SWT.TOP, true, false);
        data.widthHint = 420;
        label.setLayoutData(data);
    }

    @Override
    protected void performDefaults() {
        readOnly.setSelection(false);
        allTools.setSelection(true);
        tools.setEnabled(false);
        for (TableItem item : tools.getItems()) item.setChecked(true);
        patterns.setText("");
        allowUnencrypted.setSelection(true);
        super.performDefaults();
    }

    @Override
    public boolean performOk() {
        if (LocalPolicyStore.locked()) return true;
        try {
            List<String> parsed = LocalPolicy.parsePatterns(patterns.getText());
            Set<String> selected = null;
            if (!allTools.getSelection()) {
                selected = new LinkedHashSet<>();
                for (TableItem item : tools.getItems()) {
                    if (item.getChecked()) selected.add(item.getText());
                }
            }
            LocalPolicyStore.save(readOnly.getSelection(), selected, parsed);
            LocalPolicyStore.saveAllowUnencrypted(allowUnencrypted.getSelection());
            setErrorMessage(null);
            return true;
        } catch (IllegalArgumentException e) {
            setErrorMessage(e.getMessage());
            return false;
        } catch (IllegalStateException e) {
            setErrorMessage("The settings could not be saved.");
            return false;
        }
    }
}
