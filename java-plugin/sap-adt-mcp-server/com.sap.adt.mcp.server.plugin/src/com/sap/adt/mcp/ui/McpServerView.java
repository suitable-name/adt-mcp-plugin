package com.sap.adt.mcp.ui;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.InputDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.SWTException;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.part.ViewPart;

import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.server.RelayBridge;
import com.sap.adt.mcp.server.RelayEnrollment;
import com.sap.adt.mcp.server.RelayIdentity;
import com.sap.adt.mcp.server.RelayProfileStore;
import com.sap.adt.mcp.tools.*;

/** Manages workspace enrollment and the outbound relay connection. */
public class McpServerView extends ViewPart {
    public static final String ID = "com.sap.adt.mcp.server.view";

    private final RelayProfileStore profiles = new RelayProfileStore();
    private AdtRestClient adtClient;
    private RelayBridge bridge;
    private Thread enrollmentWorker;
    private boolean connected;
    private long generation;
    private Label status;
    private Button registerButton;
    private Button sapButton;
    private Button bridgeButton;
    private StyledText outputText;
    private String sapUrl;
    private String sapUser;
    private String sapPassword;
    private String sapClient;
    private String sapLanguage = "EN";

    @Override
    public void createPartControl(Composite parent) {
        parent.setLayout(new GridLayout(1, false));
        status = new Label(parent, SWT.WRAP);
        status.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        Composite actions = new Composite(parent, SWT.NONE);
        actions.setLayout(new RowLayout(SWT.HORIZONTAL));
        actions.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        registerButton = button(actions, "Register Eclipse", this::register);
        sapButton = button(actions, "Connect SAP", this::showConnectionDialog);
        bridgeButton = button(actions, "Connect Relay", this::toggleRelay);

        outputText = new StyledText(parent, SWT.BORDER | SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        outputText.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        outputText.setEditable(false);
        button(actions, "Clear", () -> outputText.setText(""));
        updateControls();
    }

    private static Button button(Composite parent, String text, Runnable action) {
        Button button = new Button(parent, SWT.PUSH);
        button.setText(text);
        button.addListener(SWT.Selection, event -> action.run());
        return button;
    }

    private void updateControls() {
        boolean registering = enrollmentWorker != null;
        boolean enrolled = profiles.exists();
        boolean loggedIn = adtClient != null;
        registerButton.setText(registering ? "Cancel Registration" : enrolled ? "Register Again" : "Register Eclipse");
        registerButton.setEnabled(bridge == null);
        sapButton.setEnabled(bridge == null && !registering);
        bridgeButton.setText(bridge == null ? "Connect Relay" : connected ? "Disconnect Relay" : "Cancel Connection");
        bridgeButton.setEnabled(bridge != null || loggedIn && enrolled && !registering);
        String relayStatus = registering ? "Waiting for registration" : !enrolled ? "Registration required"
                : connected ? "Relay connected" : bridge != null ? "Relay connecting" : "Relay disconnected";
        status.setText((loggedIn ? "SAP connected" : "SAP disconnected") + " | " + relayStatus);
        status.getParent().layout(true, true);
    }

    private void register() {
        if (enrollmentWorker != null) {
            cancelRegistration();
            appendOutput("Registration canceled. Discard the pending request in the relay console.\n");
            updateControls();
            return;
        }
        RelayRegistrationDialog dialog = new RelayRegistrationDialog(getSite().getShell());
        if (dialog.open() != Dialog.OK) return;
        RelayEnrollment enrollment = dialog.enrollment();
        if (profiles.exists() && !MessageDialog.openConfirm(getSite().getShell(), "Replace Registration",
                "Replace this workspace’s relay identity after the new registration succeeds?")) return;

        long attempt = ++generation;
        Display display = registerButton.getDisplay();
        appendOutput("Ask the operator to compare this request ID and the eclipse role before approval.\n"
                + enrollment.requestId() + "\n");
        enrollmentWorker = new Thread(() -> {
            try {
                RelayIdentity identity = enrollment.enroll(() -> requestToken(display, attempt, enrollment.requestId()));
                post(display, attempt, () -> {
                    try {
                        profiles.save(identity);
                        appendOutput("Eclipse registration saved.\n");
                    } catch (Exception e) {
                        appendOutput("Could not save the identity. Check Eclipse secure storage and workspace access.\n");
                    } finally {
                        enrollmentWorker = null;
                    }
                });
            } catch (RelayEnrollment.Failure e) {
                post(display, attempt, () -> {
                    enrollmentWorker = null;
                    appendOutput(e.getMessage() + "\n");
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "SAP ADT relay registration");
        enrollmentWorker.setDaemon(true);
        enrollmentWorker.start();
        updateControls();
    }

    private String requestToken(Display display, long attempt, String id) throws InterruptedException {
        CompletableFuture<String> answer = new CompletableFuture<>();
        post(display, attempt, () -> {
            InputDialog dialog = new InputDialog(getSite().getShell(), "Claim Eclipse Certificate",
                    "Enter the one-time token supplied privately by the operator for Eclipse request " + id + ".",
                    "", value -> RelayEnrollment.validTokenFormat(value) ? null : "Enter a valid approval token.") {
                @Override
                protected int getInputTextStyle() {
                    return SWT.SINGLE | SWT.BORDER | SWT.PASSWORD;
                }
            };
            answer.complete(dialog.open() == Dialog.OK && generation == attempt ? dialog.getValue().strip() : null);
        });
        try {
            return answer.get();
        } catch (ExecutionException e) {
            return null;
        }
    }

    private void cancelRegistration() {
        ++generation;
        if (enrollmentWorker != null) {
            enrollmentWorker.interrupt();
            enrollmentWorker = null;
        }
    }

    private void showConnectionDialog() {
        ConnectionDialog dialog = new ConnectionDialog(getSite().getShell());
        if (dialog.open() == Dialog.OK) {
            sapUrl = dialog.getUrl();
            sapUser = dialog.getUser();
            sapPassword = dialog.getPassword();
            sapClient = dialog.getSapClient();
            sapLanguage = dialog.getLanguage();

            // Save connection details (never password) for next time
            saveConnectionHistory();

            connectToSap();
        }
    }

    private void saveConnectionHistory() {
        try {
            org.eclipse.jface.preference.IPreferenceStore store =
                    com.sap.adt.mcp.Activator.getDefault().getPreferenceStore();

            store.setValue(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_URL, sapUrl);
            store.setValue(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_USER, sapUser);
            store.setValue(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_CLIENT, sapClient);
            store.setValue(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_LANGUAGE, sapLanguage);

            // Add URL to history (keep last 10, semicolon-separated)
            String history = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_URL_HISTORY);
            java.util.LinkedHashSet<String> urls = new java.util.LinkedHashSet<>();
            urls.add(sapUrl); // most recent first
            if (history != null && !history.isEmpty()) {
                for (String u : history.split(";")) {
                    if (!u.trim().isEmpty()) urls.add(u.trim());
                }
            }
            // Keep max 10
            StringBuilder sb = new StringBuilder();
            int count = 0;
            for (String u : urls) {
                if (count++ >= 10) break;
                if (sb.length() > 0) sb.append(";");
                sb.append(u);
            }
            store.setValue(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_URL_HISTORY, sb.toString());
        } catch (Exception e) {
            // Preference store not available, ignore
        }
    }

    private void connectToSap() {
        if (adtClient != null) adtClient.logout();
        adtClient = null;
        try {
            AdtRestClient candidate = new AdtRestClient(sapUrl, sapUser, sapPassword, sapClient, sapLanguage);
            candidate.login();
            adtClient = candidate;
            appendOutput("Connected to SAP.\n");
        } catch (Exception e) {
            appendOutput("Could not connect to SAP. Check the HTTPS URL, certificate, and login details.\n");
        } finally {
            sapPassword = null;
            updateControls();
        }
    }

    private static boolean isHttpsSapUrl(String value) {
        try {
            URI uri = URI.create(value);
            return "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                    && uri.getUserInfo() == null && uri.getQuery() == null && uri.getFragment() == null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private List<McpTool> sapTools() {
        return List.of(new SearchObjectTool(adtClient), new GetSourceTool(adtClient), new SetSourceTool(adtClient),
                new ObjectStructureTool(adtClient), new LockTool(adtClient), new UnlockTool(adtClient),
                new SyntaxCheckTool(adtClient), new ActivateTool(adtClient), new InactiveObjectsTool(adtClient),
                new CreateObjectTool(adtClient), new RunUnitTestTool(adtClient), new AtcRunTool(adtClient),
                new UsageReferencesTool(adtClient), new SqlQueryTool(adtClient), new AbapDocuTool(adtClient));
    }

    private void toggleRelay() {
        if (bridge != null) {
            disconnectRelay();
            updateControls();
            return;
        }
        RelayIdentity identity;
        try {
            identity = profiles.load();
        } catch (Exception e) {
            appendOutput("Could not unlock a valid relay identity. Check secure storage or register again.\n");
            return;
        }
        long attempt = ++generation;
        Display display = bridgeButton.getDisplay();
        bridge = new RelayBridge(identity, sapTools(), adtClient, message -> post(display, attempt, () -> {
            disconnectRelay();
            appendOutput(message + "\n");
        }));
        updateControls();
        try {
            bridge.connect().whenComplete((unused, error) -> post(display, attempt, () -> {
                if (error == null) {
                    connected = true;
                    appendOutput("Connected to the relay. SAP tools are available.\n");
                } else {
                    relayConnectionFailed(error);
                }
            }));
        } catch (RuntimeException e) {
            relayConnectionFailed(e);
            updateControls();
        }
    }

    private void relayConnectionFailed(Throwable error) {
        disconnectRelay();
        Throwable cause = error instanceof CompletionException ? error.getCause() : error;
        String message = cause instanceof RelayBridge.ConnectionFailure
                ? cause.getMessage() : "Could not start the relay connection.";
        appendOutput(message + "\n");
    }

    private void post(Display display, long attempt, Runnable action) {
        try {
            display.asyncExec(() -> {
                if (!status.isDisposed() && generation == attempt) {
                    action.run();
                    if (!status.isDisposed()) updateControls();
                }
            });
        } catch (SWTException e) {
            if (e.code != SWT.ERROR_DEVICE_DISPOSED) throw e;
        }
    }

    private void disconnectRelay() {
        ++generation;
        connected = false;
        if (bridge != null) {
            bridge.close();
            bridge = null;
        }
    }

    private void appendOutput(String text) {
        if (outputText != null && !outputText.isDisposed()) {
            outputText.append(text);
            outputText.setTopIndex(outputText.getLineCount() - 1);
        }
    }

    @Override
    public void setFocus() {
        if (outputText != null && !outputText.isDisposed()) {
            outputText.setFocus();
        }
    }

    @Override
    public void dispose() {
        cancelRegistration();
        disconnectRelay();
        if (adtClient != null) adtClient.logout();
        super.dispose();
    }

    /**
     * Connection dialog for SAP system details.
     * Loads previous connection details from preferences (except password).
     */
    private class ConnectionDialog extends Dialog {
        private org.eclipse.swt.widgets.Combo urlCombo;
        private Text userText;
        private Text passwordText;
        private Text clientText;
        private Text languageText;

        private String url;
        private String user;
        private String password;
        private String client;
        private String language;

        protected ConnectionDialog(Shell parentShell) {
            super(parentShell);
        }

        @Override
        protected void configureShell(Shell shell) {
            super.configureShell(shell);
            shell.setText("Connect to SAP System");
        }

        @Override
        protected Control createDialogArea(Composite parent) {
            Composite container = (Composite) super.createDialogArea(parent);
            container.setLayout(new GridLayout(2, false));

            // Load saved values from preferences
            String savedUrl = "";
            String savedUser = "";
            String savedClient = "100";
            String savedLanguage = "EN";
            String[] urlHistory = new String[0];

            try {
                org.eclipse.jface.preference.IPreferenceStore store =
                        com.sap.adt.mcp.Activator.getDefault().getPreferenceStore();
                savedUrl = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_URL);
                savedUser = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_USER);
                savedClient = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_CLIENT);
                savedLanguage = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_LAST_LANGUAGE);
                String history = store.getString(com.sap.adt.mcp.preferences.PreferenceInitializer.PREF_URL_HISTORY);
                if (history != null && !history.isEmpty()) {
                    urlHistory = history.split(";");
                }
            } catch (Exception e) {
                // Preferences not available
            }

            // Use saved values, fall back to current session values, then defaults
            String defaultUrl = !savedUrl.isEmpty() ? savedUrl : (sapUrl != null ? sapUrl : "");
            String defaultUser = !savedUser.isEmpty() ? savedUser : (sapUser != null ? sapUser : "");
            String defaultClient = !savedClient.isEmpty() ? savedClient : (sapClient != null ? sapClient : "100");
            String defaultLanguage = !savedLanguage.isEmpty() ? savedLanguage : (sapLanguage != null ? sapLanguage : "EN");

            new Label(container, SWT.NONE).setText("SAP URL:");
            urlCombo = new org.eclipse.swt.widgets.Combo(container, SWT.BORDER);
            urlCombo.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
            // Populate URL dropdown with history
            for (String histUrl : urlHistory) {
                if (!histUrl.trim().isEmpty()) {
                    urlCombo.add(histUrl.trim());
                }
            }
            urlCombo.setText(defaultUrl);

            new Label(container, SWT.NONE).setText("User:");
            userText = new Text(container, SWT.BORDER);
            userText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
            userText.setText(defaultUser);

            new Label(container, SWT.NONE).setText("Password:");
            passwordText = new Text(container, SWT.BORDER | SWT.PASSWORD);
            passwordText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));

            new Label(container, SWT.NONE).setText("Client:");
            clientText = new Text(container, SWT.BORDER);
            clientText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
            clientText.setText(defaultClient);

            new Label(container, SWT.NONE).setText("Language:");
            languageText = new Text(container, SWT.BORDER);
            languageText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
            languageText.setText(defaultLanguage);

            // Focus password field since other fields are pre-filled
            container.getDisplay().asyncExec(() -> passwordText.setFocus());

            return container;
        }

        @Override
        protected void createButtonsForButtonBar(Composite parent) {
            createButton(parent, IDialogConstants.OK_ID, "Connect", true);
            createButton(parent, IDialogConstants.CANCEL_ID, IDialogConstants.CANCEL_LABEL, false);
        }

        @Override
        protected void okPressed() {
            url = urlCombo.getText().trim();
            if (!isHttpsSapUrl(url)) {
                org.eclipse.jface.dialogs.MessageDialog.openError(getShell(), "SAP Connection",
                        "Enter an HTTPS base URL for the SAP system to use the company relay.");
                urlCombo.setFocus();
                return;
            }
            user = userText.getText().trim();
            password = passwordText.getText();
            client = clientText.getText().trim();
            language = languageText.getText().trim();
            super.okPressed();
        }

        public String getUrl() { return url; }
        public String getUser() { return user; }
        public String getPassword() { return password; }
        public String getSapClient() { return client; }
        public String getLanguage() { return language; }
    }
}
