package com.sap.adt.mcp.ui;

import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import com.sap.adt.mcp.server.RelayEnrollment;
import com.sap.adt.mcp.server.RelayLink;

final class RelayRegistrationDialog extends TitleAreaDialog {
    private static final String NOT_ECLIPSE = "This link is for another role. Ask the relay operator for an eclipse link.";
    private Text linkText;
    private Label relayLine;
    private RelayLink parsed;
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
        setMessage("Paste the enrollment link the relay operator gave you for the eclipse role.");
        Composite fields = new Composite(area, SWT.NONE);
        fields.setLayout(new GridLayout(1, false));
        fields.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        new Label(fields, SWT.NONE).setText("Enrollment link");
        linkText = new Text(fields, SWT.BORDER | SWT.MULTI | SWT.WRAP | SWT.V_SCROLL);
        linkText.setMessage("sap-adt://enroll?...");
        GridData data = new GridData(SWT.FILL, SWT.FILL, true, true);
        data.heightHint = linkText.getLineHeight() * 5;
        data.widthHint = 480;
        linkText.setLayoutData(data);
        relayLine = new Label(fields, SWT.NONE);
        relayLine.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        linkText.addModifyListener(event -> validate());
        return area;
    }

    @Override
    protected void createButtonsForButtonBar(Composite parent) {
        createButton(parent, IDialogConstants.OK_ID, "Register", true);
        createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
        validate();
    }

    /** Pasted links may carry line breaks and surrounding whitespace; the parser strips both. */
    private static String pasted(String text) {
        StringBuilder compact = new StringBuilder(text.length());
        text.strip().chars().filter(c -> !Character.isWhitespace(c)).forEach(c -> compact.append((char) c));
        return compact.toString();
    }

    private void validate() {
        if (parsed != null) {
            parsed.wipe();
            parsed = null;
        }
        String message = null;
        String relay = "";
        String text = pasted(linkText.getText());
        if (!text.isEmpty()) {
            try {
                RelayLink link = RelayLink.parse(text);
                if (link.kind() != RelayLink.Kind.ENROLL || link.role() != RelayLink.Role.ECLIPSE) {
                    link.wipe();
                    message = link.kind() == RelayLink.Kind.ENROLL ? NOT_ECLIPSE
                            : "This is a pairing link. Paste it into the desktop client, not here.";
                } else {
                    parsed = link;
                    relay = "Relay: " + (link.name().isEmpty() ? "(unnamed)" : link.name()) + " · role: "
                            + link.role().word();
                }
            } catch (RelayLink.LinkException e) {
                message = e.getMessage();
            }
        }
        setErrorMessage(message);
        relayLine.setText(relay);
        Button ok = getButton(IDialogConstants.OK_ID);
        if (ok != null) ok.setEnabled(parsed != null);
    }

    @Override
    protected void okPressed() {
        if (parsed == null) return;
        try {
            enrollment = new RelayEnrollment(parsed);
        } catch (IllegalArgumentException e) {
            setErrorMessage("This link has an address Eclipse cannot use. Ask the relay operator for a new link.");
            return;
        }
        parsed = null; // the enrollment owns the link and wipes it after the claim
        linkText.setText("");
        super.okPressed();
    }

    @Override
    public boolean close() {
        if (parsed != null) {
            parsed.wipe();
            parsed = null;
        }
        if (linkText != null && !linkText.isDisposed()) linkText.setText("");
        return super.close();
    }

    RelayEnrollment enrollment() {
        return enrollment;
    }
}
