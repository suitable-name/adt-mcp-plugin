package com.sap.adt.mcp.preferences;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import com.sap.adt.mcp.server.LocalPolicy;
import com.sap.adt.mcp.server.E2eServices;
import com.sap.adt.mcp.server.e2e.Pairing;
import com.sap.adt.mcp.server.e2e.PinStore;
import com.sap.adt.mcp.tools.ToolCatalog;

/** MCP Relay, Permissions: what this Eclipse allows a relay to do. These settings can only restrict. */
public class PermissionsPreferencePage extends PreferencePage implements IWorkbenchPreferencePage {
    private Button readOnly;
    private Button allTools;
    private Button allowUnencrypted;
    private Table tools;
    private Text patterns;
    private Table desktops;
    private Button editDesktop;
    /** Per-desktop changes made on this page, written by {@link #performOk()}. Keyed by key fingerprint. */
    private final Map<String, DesktopPermissionsDialog.Values> pendingDesktops = new HashMap<>();

    @Override
    public void init(IWorkbench workbench) {
        setDescription("Limits applied in this Eclipse in addition to the relay's own rules. "
                + "They can only restrict what the relay allows. Changes apply to the next call.");
    }

    @Override
    protected Control createContents(Composite parent) {
        Composite page = new Composite(parent, SWT.NONE);
        page.setLayout(new GridLayout(1, false));
        boolean locked = LocalPolicyStore.locked();
        LocalPolicy current = LocalPolicyStore.load();
        if (locked) {
            Label notice = new Label(page, SWT.WRAP);
            notice.setText("Locked by your administrator. These values cannot be changed here.");
        }

        readOnly = new Button(page, SWT.CHECK);
        readOnly.setText("Read-only: allow only tools that read from SAP");
        readOnly.setSelection(current.readOnly());

        allTools = new Button(page, SWT.CHECK);
        allTools.setText("Allow all tools");
        allTools.setSelection(current.allowedTools() == null);
        allTools.addListener(SWT.Selection, event -> tools.setEnabled(!allTools.getSelection() && !locked));

        tools = new Table(page, SWT.BORDER | SWT.CHECK | SWT.V_SCROLL);
        tools.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        ToolCatalog catalog = ToolCatalog.bundled();
        for (String name : new TreeSet<>(catalog.names())) {
            TableItem item = new TableItem(tools, SWT.NONE);
            item.setText(name);
            item.setChecked(current.allowedTools() == null || current.allowedTools().contains(name));
        }
        tools.setEnabled(current.allowedTools() != null && !locked);

        Label patternLabel = new Label(page, SWT.WRAP);
        patternLabel.setText("Package patterns (comma or line separated, for example Z*, /NS/*). "
                + "Empty means no local package restriction. With patterns, only tools that work on a known package are allowed.");
        patterns = new Text(page, SWT.BORDER | SWT.MULTI | SWT.WRAP | SWT.V_SCROLL);
        GridData patternData = new GridData(SWT.FILL, SWT.FILL, true, false);
        patternData.heightHint = 60;
        patterns.setLayoutData(patternData);
        patterns.setText(String.join(", ", current.packagePatterns()));

        allowUnencrypted = new Button(page, SWT.CHECK);
        allowUnencrypted.setText("Allow unencrypted relay calls");
        allowUnencrypted.setSelection(LocalPolicyStore.allowUnencrypted());
        Label unencryptedNote = new Label(page, SWT.WRAP);
        unencryptedNote.setText("When off, this Eclipse only answers end-to-end encrypted requests from paired "
                + "desktops. A compromised relay can then neither read nor send SAP calls.");
        GridData noteData = new GridData(SWT.FILL, SWT.TOP, true, false);
        noteData.widthHint = 400;
        unencryptedNote.setLayoutData(noteData);

        createDesktopSection(page, locked);

        if (locked) {
            allowUnencrypted.setEnabled(false);
            readOnly.setEnabled(false);
            allTools.setEnabled(false);
            patterns.setEditable(false);
            noDefaultAndApplyButton();
        }
        return page;
    }

    /** One row per paired desktop; its settings apply in addition to the global ones above. */
    private void createDesktopSection(Composite page, boolean locked) {
        Label desktopLabel = new Label(page, SWT.WRAP);
        desktopLabel.setText("Paired desktops. Each desktop can be limited further than the settings above. "
                + "A desktop left at \"Same as global\" gets only the global permissions.");
        desktops = new Table(page, SWT.BORDER | SWT.FULL_SELECTION | SWT.V_SCROLL);
        desktops.setHeaderVisible(true);
        GridData desktopData = new GridData(SWT.FILL, SWT.FILL, true, false);
        desktopData.heightHint = 90;
        desktops.setLayoutData(desktopData);
        for (String title : new String[] {"Desktop", "Key", "Permissions"}) {
            TableColumn column = new TableColumn(desktops, SWT.NONE);
            column.setText(title);
            column.setWidth(title.equals("Desktop") ? 180 : title.equals("Key") ? 150 : 150);
        }
        for (PinStore.Pin pin : E2eServices.pinStore().list()) {
            TableItem item = new TableItem(desktops, SWT.NONE);
            item.setData(pin.keyFingerprint());
            item.setText(0, pin.label());
            item.setText(1, Pairing.shortFingerprint(pin.keyFingerprint()));
            item.setText(2, describe(DesktopPermissionsDialog.Values.of(LocalPolicyStore.loadDesktop(pin.keyFingerprint()))));
        }
        editDesktop = new Button(page, SWT.PUSH);
        editDesktop.setText("Edit desktop permissions...");
        editDesktop.setEnabled(false);
        editDesktop.addListener(SWT.Selection, event -> editSelectedDesktop());
        desktops.addListener(SWT.Selection, event -> editDesktop.setEnabled(!locked && desktops.getSelectionCount() == 1));
    }

    private static String describe(DesktopPermissionsDialog.Values values) {
        return values.sameAsGlobal() ? "Same as global" : "Custom";
    }

    private void editSelectedDesktop() {
        if (desktops.getSelectionCount() != 1) return;
        TableItem item = desktops.getSelection()[0];
        String fingerprint = (String) item.getData();
        DesktopPermissionsDialog.Values start = pendingDesktops.get(fingerprint);
        if (start == null) start = DesktopPermissionsDialog.Values.of(LocalPolicyStore.loadDesktop(fingerprint));
        DesktopPermissionsDialog dialog = new DesktopPermissionsDialog(getShell(), item.getText(0),
                item.getText(1), start);
        if (dialog.open() == org.eclipse.jface.window.Window.OK && dialog.result() != null) {
            pendingDesktops.put(fingerprint, dialog.result());
            item.setText(2, describe(dialog.result()));
        }
    }

    @Override
    protected void performDefaults() {
        readOnly.setSelection(false);
        allTools.setSelection(true);
        tools.setEnabled(false);
        for (TableItem item : tools.getItems()) item.setChecked(true);
        patterns.setText("");
        allowUnencrypted.setSelection(true);
        for (TableItem item : desktops.getItems()) {
            pendingDesktops.put((String) item.getData(), DesktopPermissionsDialog.Values.same());
            item.setText(2, "Same as global");
        }
        super.performDefaults();
    }

    @Override
    public boolean performOk() {
        if (LocalPolicyStore.locked()) return true;
        try {
            LocalPolicy.parsePatterns(patterns.getText()); // reject a bad global pattern before anything is written
            for (Map.Entry<String, DesktopPermissionsDialog.Values> entry : pendingDesktops.entrySet()) {
                DesktopPermissionsDialog.Values values = entry.getValue();
                if (values.sameAsGlobal()) {
                    LocalPolicyStore.resetDesktop(entry.getKey());
                } else {
                    LocalPolicyStore.saveDesktop(entry.getKey(), values.readOnly(), values.tools(), values.patterns());
                }
            }
            pendingDesktops.clear();
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
            setErrorMessage("The permissions could not be saved.");
            return false;
        }
    }
}
