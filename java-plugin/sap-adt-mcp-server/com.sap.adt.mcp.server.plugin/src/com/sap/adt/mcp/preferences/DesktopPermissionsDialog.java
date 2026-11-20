package com.sap.adt.mcp.preferences;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;

import com.sap.adt.mcp.server.LocalPolicy;
import com.sap.adt.mcp.tools.ToolCatalog;

/**
 * The three permission settings for one paired desktop. Whatever is set here applies in addition to the global
 * permissions, so it can only restrict further; leaving a setting at its default means "same as global".
 */
final class DesktopPermissionsDialog extends Dialog {
    private static final int SAME_AS_GLOBAL_ID = IDialogConstants.CLIENT_ID + 1;

    /** What the user chose. {@code tools == null} means all tools. */
    record Values(boolean sameAsGlobal, boolean readOnly, Set<String> tools, List<String> patterns) {
        static Values same() {
            return new Values(true, false, null, List.of());
        }

        static Values of(LocalPolicy policy) {
            boolean custom = policy.readOnly() || policy.allowedTools() != null || !policy.packagePatterns().isEmpty();
            return custom ? new Values(false, policy.readOnly(), policy.allowedTools(), policy.packagePatterns()) : same();
        }
    }

    private final String desktopLabel;
    private final String shortFingerprint;
    private final Values initial;
    private Button readOnly;
    private Button allTools;
    private Table tools;
    private Text patterns;
    private Values result;

    DesktopPermissionsDialog(Shell parent, String desktopLabel, String shortFingerprint, Values initial) {
        super(parent);
        this.desktopLabel = desktopLabel;
        this.shortFingerprint = shortFingerprint;
        this.initial = initial;
    }

    /** The chosen values after OK or "Same as global"; null after Cancel. */
    Values result() {
        return result;
    }

    @Override
    protected void configureShell(Shell shell) {
        super.configureShell(shell);
        shell.setText("Permissions for " + desktopLabel);
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite area = (Composite) super.createDialogArea(parent);
        Label intro = new Label(area, SWT.WRAP);
        intro.setText(desktopLabel + " (key " + shortFingerprint + "). These settings apply in addition to the global "
                + "permissions and can only restrict further. A setting left at its default is the same as global.");
        GridData introData = new GridData(SWT.FILL, SWT.CENTER, true, false);
        introData.widthHint = 420;
        intro.setLayoutData(introData);

        readOnly = new Button(area, SWT.CHECK);
        readOnly.setText("Read-only for this desktop");
        readOnly.setSelection(initial.readOnly());

        allTools = new Button(area, SWT.CHECK);
        allTools.setText("Allow all tools (that the global permissions allow)");
        allTools.setSelection(initial.tools() == null);
        allTools.addListener(SWT.Selection, event -> tools.setEnabled(!allTools.getSelection()));

        tools = new Table(area, SWT.BORDER | SWT.CHECK | SWT.V_SCROLL);
        GridData toolData = new GridData(SWT.FILL, SWT.FILL, true, true);
        toolData.heightHint = 160;
        tools.setLayoutData(toolData);
        for (String name : new TreeSet<>(ToolCatalog.bundled().names())) {
            TableItem item = new TableItem(tools, SWT.NONE);
            item.setText(name);
            item.setChecked(initial.tools() == null || initial.tools().contains(name));
        }
        tools.setEnabled(initial.tools() != null);

        Label patternLabel = new Label(area, SWT.WRAP);
        patternLabel.setText("Package patterns (for example Z*, /NS/*). Empty means the same as global.");
        patterns = new Text(area, SWT.BORDER | SWT.MULTI | SWT.WRAP | SWT.V_SCROLL);
        GridData patternData = new GridData(SWT.FILL, SWT.FILL, true, false);
        patternData.heightHint = 50;
        patterns.setLayoutData(patternData);
        patterns.setText(String.join(", ", initial.patterns()));
        return area;
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, SAME_AS_GLOBAL_ID, "Same as global", false);
        createButton(parent, IDialogConstants.OK_ID, IDialogConstants.OK_LABEL, true);
        createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
    }

    @Override
    protected void buttonPressed(int buttonId) {
        if (buttonId == SAME_AS_GLOBAL_ID) {
            result = Values.same();
            setReturnCode(OK);
            close();
            return;
        }
        super.buttonPressed(buttonId);
    }

    @Override
    protected void okPressed() {
        List<String> parsed;
        try {
            parsed = LocalPolicy.parsePatterns(patterns.getText());
        } catch (IllegalArgumentException e) {
            org.eclipse.jface.dialogs.MessageDialog.openError(getShell(), "Package patterns", e.getMessage());
            return;
        }
        Set<String> selected = null;
        if (!allTools.getSelection()) {
            selected = new LinkedHashSet<>();
            for (TableItem item : tools.getItems()) {
                if (item.getChecked()) selected.add(item.getText());
            }
        }
        boolean none = !readOnly.getSelection() && selected == null && parsed.isEmpty();
        result = none ? Values.same() : new Values(false, readOnly.getSelection(), selected, parsed);
        super.okPressed();
    }
}
