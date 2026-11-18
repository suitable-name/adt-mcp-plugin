package com.sap.adt.mcp.ui;

import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import com.sap.adt.mcp.server.RelayEnrollment;

final class RelayRegistrationDialog extends TitleAreaDialog {
    private Text label;
    private Text registrationUrl;
    private Text bridgeUrl;
    private RelayEnrollment enrollment;

    RelayRegistrationDialog(Shell parent) {
        super(parent);
    }

    @Override
    protected void configureShell(Shell shell) {
        super.configureShell(shell);
        shell.setText("Register Eclipse");
    }

    @Override
    protected Control createDialogArea(Composite parent) {
        Composite area = (Composite) super.createDialogArea(parent);
        setTitle("Register Eclipse");
        setMessage("The relay operator will compare your request ID and give you a one-time token.");
        Composite fields = new Composite(area, SWT.NONE);
        fields.setLayout(new GridLayout(2, false));
        fields.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        label = field(fields, "Device Label", "");
        registrationUrl = field(fields, "Registration URL", "https://relay.example.com:8788");
        bridgeUrl = field(fields, "Bridge URL", "wss://relay.example.com:8787/bridge");
        return area;
    }

    private static Text field(Composite parent, String name, String hint) {
        new Label(parent, SWT.NONE).setText(name);
        Text input = new Text(parent, SWT.BORDER);
        input.setMessage(hint);
        input.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        return input;
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, IDialogConstants.OK_ID, "Request Registration", true);
        createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
    }

    @Override
    protected void okPressed() {
        try {
            enrollment = new RelayEnrollment(label.getText().strip(), registrationUrl.getText().strip(),
                    bridgeUrl.getText().strip());
        } catch (IllegalArgumentException e) {
            setErrorMessage("Enter a device label of up to 64 printable ASCII characters, an HTTPS registration URL, and a WSS /bridge URL.");
            return;
        }
        super.okPressed();
    }

    RelayEnrollment enrollment() {
        return enrollment;
    }
}
