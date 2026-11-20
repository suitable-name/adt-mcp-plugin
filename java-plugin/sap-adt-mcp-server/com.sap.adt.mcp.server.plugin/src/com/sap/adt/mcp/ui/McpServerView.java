package com.sap.adt.mcp.ui;

import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletableFuture;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.SWT;
import org.eclipse.swt.SWTException;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.dialogs.ElementListSelectionDialog;
import org.eclipse.ui.part.ViewPart;

import com.sap.adt.destinations.ui.logon.AdtLogonServiceUIFactory;
import com.sap.adt.mcp.Activator;
import com.sap.adt.mcp.preferences.LocalPolicyStore;
import com.sap.adt.mcp.preferences.PreferenceInitializer;
import com.sap.adt.mcp.server.PolicyDenials;
import com.sap.adt.mcp.sap.AdtProjectClient;
import com.sap.adt.mcp.server.LegacyCalls;
import com.sap.adt.mcp.server.RelayBridge;
import com.sap.adt.mcp.server.RelayEnrollment;
import com.sap.adt.mcp.server.RelayIdentity;
import com.sap.adt.mcp.server.RelayProfileStore;
import com.sap.adt.mcp.server.ToolExecutor;
import com.sap.adt.mcp.server.e2e.E2eServices;
import com.sap.adt.mcp.server.e2e.Pairing;
import com.sap.adt.mcp.server.e2e.PinStore;
import com.sap.adt.mcp.server.e2e.StreamRequests;
import com.sap.adt.mcp.tools.*;
import com.sap.adt.tools.core.project.AdtProjectServiceFactory;
import com.sap.adt.tools.core.project.IAbapProject;

/** Manages workspace enrollment and the outbound relay connection. */
public class McpServerView extends ViewPart {
    public static final String ID = "com.sap.adt.mcp.server.view";

    private final RelayProfileStore profiles = new RelayProfileStore();
    private AdtProjectClient adtClient;
    private IProject selectedProject;
    private boolean selectingProject;
    private RelayBridge bridge;
    private Thread enrollmentWorker;
    private boolean connected;
    private long generation;
    private Label status;
    private Label policyLine;
    private final java.util.function.Consumer<String> denialListener = line -> {
        Display display = status == null || status.isDisposed() ? null : status.getDisplay();
        if (display == null || display.isDisposed()) return;
        try {
            display.asyncExec(() -> appendOutput(line + "\n"));
        } catch (SWTException e) {
            // The display is going away.
        }
    };
    private Button registerButton;
    private Button sapButton;
    private Button bridgeButton;
    private StyledText outputText;
    // Encrypted streams: pairing and paired desktops (created when the relay connection is built).
    private Pairing pairing;
    private Button pairButton;
    private Button copyLinkButton;
    private Text pairLinkText;
    private Label pairRemaining;
    private Table pairedTable;
    private Button removePairedButton;
    private final Runnable pinListener = () -> {
        Display display = pairedTable == null || pairedTable.isDisposed() ? null : pairedTable.getDisplay();
        if (display == null || display.isDisposed()) return;
        try {
            display.asyncExec(this::refreshPaired);
        } catch (SWTException e) {
            // The display is going away.
        }
    };

    @Override
    public void createPartControl(Composite parent) {
        parent.setLayout(new GridLayout(1, false));
        status = new Label(parent, SWT.WRAP);
        status.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        policyLine = new Label(parent, SWT.WRAP);
        policyLine.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        PolicyDenials.addListener(denialListener);
        Composite actions = new Composite(parent, SWT.NONE);
        actions.setLayout(new RowLayout(SWT.HORIZONTAL));
        actions.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        registerButton = button(actions, "Register Eclipse", this::register);
        sapButton = button(actions, "Select ABAP Project", this::selectProject);
        bridgeButton = button(actions, "Connect Relay", this::toggleRelay);
        createPairingControls(parent);

        outputText =new StyledText(parent, SWT.BORDER | SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        outputText.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        outputText.setEditable(false);
        button(actions, "Clear", () -> outputText.setText(""));
        restoreSelectedProject();
        updateControls();
        parent.getDisplay().timerExec(1000, this::checkProjectConnection);
    }

    private void createPairingControls(Composite parent) {
        Composite pairActions = new Composite(parent, SWT.NONE);
        pairActions.setLayout(new RowLayout(SWT.HORIZONTAL));
        pairActions.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        pairButton = button(pairActions, "Pair Desktop", this::pairDesktop);
        copyLinkButton = button(pairActions, "Copy", this::copyPairingLink);
        pairRemaining = new Label(pairActions, SWT.NONE);
        pairLinkText = new Text(parent, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP);
        GridData linkData = new GridData(SWT.FILL, SWT.CENTER, true, false);
        linkData.heightHint = 40;
        pairLinkText.setLayoutData(linkData);
        showPairing(null);

        Label pairedLabel = new Label(parent, SWT.NONE);
        pairedLabel.setText("Paired desktops");
        pairedTable = new Table(parent, SWT.BORDER | SWT.FULL_SELECTION | SWT.V_SCROLL);
        pairedTable.setHeaderVisible(true);
        GridData tableData = new GridData(SWT.FILL, SWT.CENTER, true, false);
        tableData.heightHint = 70;
        pairedTable.setLayoutData(tableData);
        for (String title : new String[] {"Desktop", "Key", "Paired since"}) {
            TableColumn column = new TableColumn(pairedTable, SWT.NONE);
            column.setText(title);
            column.setWidth(title.equals("Paired since") ? 180 : 160);
        }
        removePairedButton = button(parent, "Remove", this::removePaired);
        pairedTable.addListener(SWT.Selection, event -> removePairedButton.setEnabled(pairedTable.getSelectionCount() == 1));
        E2eServices.pinStore().addListener(pinListener);
        refreshPaired();
    }

    private void refreshPaired() {
        if (pairedTable == null || pairedTable.isDisposed()) return;
        pairedTable.removeAll();
        for (PinStore.Pin pin : E2eServices.pinStore().list()) {
            TableItem item = new TableItem(pairedTable, SWT.NONE);
            item.setData(pin.keyFingerprint());
            item.setText(0, pin.label());
            item.setText(1, Pairing.shortFingerprint(pin.keyFingerprint()));
            item.setText(2, String.valueOf(pin.pairedAt()));
        }
        removePairedButton.setEnabled(false);
    }

    private void removePaired() {
        if (pairedTable.getSelectionCount() != 1) return;
        TableItem item = pairedTable.getSelection()[0];
        String fingerprint = (String) item.getData();
        String label = item.getText(0);
        if (!MessageDialog.openConfirm(getSite().getShell(), "Remove Paired Desktop",
                "Remove " + label + "? It must be paired again before it can use this Eclipse.")) return;
        E2eServices.pinStore().remove(fingerprint);
        LocalPolicyStore.forgetDesktop(fingerprint);
        appendOutput("Removed paired desktop " + label + ".\n");
    }

    private void pairDesktop() {
        if (pairing == null || !connected) return;
        try {
            String link = pairing.mint();
            showPairing(link);
            appendOutput("Pairing link created. Copy it on this machine and paste it into the desktop client. "
                    + "It works once and expires in " + Pairing.LIFETIME.toMinutes() + " minutes.\n");
        } catch (IllegalStateException e) {
            appendOutput("Could not create a pairing link.\n");
        }
    }

    private void copyPairingLink() {
        String link = pairLinkText.getText();
        if (link.isEmpty()) return;
        Clipboard clipboard = new Clipboard(pairLinkText.getDisplay());
        try {
            clipboard.setContents(new Object[] {link}, new Transfer[] {TextTransfer.getInstance()});
        } finally {
            clipboard.dispose();
        }
    }

    /** Shows the link, or clears the area when {@code link} is null. */
    private void showPairing(String link) {
        pairLinkText.setText(link == null ? "" : link);
        boolean has = link != null;
        pairLinkText.setVisible(has);
        ((GridData) pairLinkText.getLayoutData()).exclude = !has;
        copyLinkButton.setEnabled(has);
        pairRemaining.setText("");
        pairRemaining.getParent().getParent().layout(true, true);
    }

    /** Called every second: shows the remaining lifetime and clears the link once it is used or expired. */
    private void refreshPairingLine() {
        if (pairLinkText == null || pairLinkText.isDisposed()) return;
        boolean shown = !pairLinkText.getText().isEmpty();
        Instant expires = pairing == null ? null : pairing.expiresAt();
        if (expires == null) {
            if (shown) showPairing(null);
            return;
        }
        long seconds = Math.max(0, Duration.between(Instant.now(), expires).getSeconds());
        pairRemaining.setText("Link valid for " + seconds / 60 + ":" + String.format("%02d", seconds % 60));
        pairRemaining.getParent().layout(true, true);
    }

    /** The non-blocking "Pair <label>?" dialog (D12). Called from a transport thread. */
    private CompletableFuture<Boolean> confirmPairing(String relayLabel, String shortFingerprint) {
        CompletableFuture<Boolean> answer = new CompletableFuture<>();
        Display display = pairedTable == null || pairedTable.isDisposed() ? null : pairedTable.getDisplay();
        if (display == null || display.isDisposed()) {
            answer.complete(false);
            return answer;
        }
        try {
            display.asyncExec(() -> {
                Shell parent = display.getActiveShell();
                MessageDialog dialog = new MessageDialog(parent, "Pair Desktop", null,
                        "Pair " + relayLabel + "?\n\nThe label comes from the relay and is not verified.\n"
                                + "Desktop key: " + shortFingerprint + "\n\nCompare this key with the one the "
                                + "desktop client printed. Pairing lets that desktop use this Eclipse's SAP session.",
                        MessageDialog.QUESTION, new String[] {"Pair", "Refuse"}, 1) {
                    @Override
                    protected void buttonPressed(int buttonId) {
                        answer.complete(buttonId == 0);
                        super.buttonPressed(buttonId);
                    }

                    @Override
                    public boolean close() {
                        answer.complete(false);
                        return super.close();
                    }
                };
                dialog.setBlockOnOpen(false);
                dialog.open();
                // Pairing cancels the answer when the user takes too long; close the dialog then.
                answer.whenComplete((value, error) -> {
                    if (!display.isDisposed()) {
                        display.asyncExec(() -> {
                            if (dialog.getShell() != null && !dialog.getShell().isDisposed()) dialog.close();
                        });
                    }
                });
            });
        } catch (SWTException e) {
            answer.complete(false);
        }
        return answer;
    }

    /** Builds the encrypted-stream handler for this connection and hands it to the transport. */
    private void installStreams(RelayIdentity identity) throws GeneralSecurityException, IOException {
        ToolExecutor executor = new ToolExecutor(sapTools(), adtClient);
        Pairing created = new Pairing(identity.relayFingerprint(), identity.label(),
                E2eServices.innerKeys()::fingerprintBytes, E2eServices.pinStore()::add, this::confirmPairing,
                PolicyDenials::report);
        String version = Activator.getDefault().getBundle().getVersion().toString();
        pairing = created;
        E2eServices.setHandler(new StreamRequests(executor, created, LocalPolicyStore::effectiveFor, version));
        E2eServices.setPairingGate(created);
    }

    private void uninstallStreams() {
        E2eServices.setHandler(null);
        E2eServices.setPairingGate(() -> false);
        if (pairing != null) pairing.cancel();
        pairing = null;
        if (pairLinkText != null && !pairLinkText.isDisposed()) showPairing(null);
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
        boolean hasProject = selectedProject != null && selectedProject.isAccessible();
        registerButton.setText(registering ? "Cancel Registration" : enrolled ? "Register Again" : "Register Eclipse");
        registerButton.setEnabled(bridge == null && !selectingProject);
        sapButton.setEnabled(bridge == null && !registering && !selectingProject);
        bridgeButton.setText(bridge == null ? "Connect Relay" : connected ? "Disconnect Relay" : "Cancel Connection");
        bridgeButton.setEnabled(!selectingProject && (bridge != null || hasProject && enrolled && !registering));
        String relayStatus = registering ? "Waiting for registration" : !enrolled ? "Registration required"
                : connected ? "Relay connected" : bridge != null ? "Relay connecting" : "Relay disconnected";
        String projectStatus = selectingProject ? "Opening ADT project" : !hasProject ? "Select an ABAP project"
                : "ABAP project " + selectedProject.getName();
        if (!selectingProject && adtClient != null) projectStatus += " · " + adtClient.getUsername();
        status.setText(projectStatus + " | " + relayStatus);
        pairButton.setEnabled(connected && pairing != null);
        refreshPolicyLine();
        status.getParent().layout(true, true);
    }

    private void refreshPolicyLine() {
        String text = LocalPolicyStore.load().summary() + " | Unencrypted relay calls: "
                + (LocalPolicyStore.allowUnencrypted() ? "allowed" : "blocked");
        if (!text.equals(policyLine.getText())) {
            policyLine.setText(text);
            policyLine.getParent().layout(true, true);
        }
    }

    private void register() {
        if (enrollmentWorker != null) {
            cancelRegistration();
            appendOutput("Registration canceled.\n");
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
        appendOutput("Registering this Eclipse with the relay.\n");
        enrollmentWorker = new Thread(() -> {
            try {
                RelayIdentity identity = enrollment.enroll();
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

    private void cancelRegistration() {
        ++generation;
        if (enrollmentWorker != null) {
            enrollmentWorker.interrupt();
            enrollmentWorker = null;
        }
    }

    private void restoreSelectedProject() {
        String name = Activator.getDefault().getPreferenceStore().getString(PreferenceInitializer.PREF_LAST_PROJECT);
        if (name.isEmpty()) return;
        for (IProject project : ResourcesPlugin.getWorkspace().getRoot().getProjects()) {
            if (project.getName().equals(name) && project.isAccessible()
                    && project.getAdapter(IAbapProject.class) != null) {
                selectedProject = project;
                return;
            }
        }
    }

    private void selectProject() {
        if (bridge != null || selectingProject) return;
        ElementListSelectionDialog dialog = new ElementListSelectionDialog(getSite().getShell(), new LabelProvider() {
            @Override
            public String getText(Object element) {
                return ((IProject) element).getName();
            }
        });
        dialog.setTitle("Select ABAP Project");
        dialog.setMessage("Select an existing ABAP project. ADT will open its standard logon dialog if needed.");
        dialog.setEmptyListMessage("No ABAP projects are available. Open an ABAP project in Project Explorer first.");
        dialog.setMultipleSelection(false);
        dialog.setElements(AdtProjectServiceFactory.createProjectService().getAvailableAbapProjects());
        if (selectedProject != null) dialog.setInitialSelections(new Object[] { selectedProject });
        if (dialog.open() == Dialog.OK && !status.isDisposed()) {
            prepareProject((IProject) dialog.getFirstResult());
        }
    }

    private boolean prepareProject(IProject project) {
        if (status.isDisposed()) return false;
        if (project == null || !project.isAccessible()) {
            appendOutput("Select an open ABAP project from this Eclipse workspace.\n");
            return false;
        }
        if (project.equals(selectedProject) && adtClient != null && adtClient.isLoggedIn()) return true;
        IAbapProject abapProject = project.getAdapter(IAbapProject.class);
        if (abapProject == null) {
            appendOutput("The selected project is not an ABAP project.\n");
            return false;
        }
        long attempt = ++generation;
        selectingProject = true;
        updateControls();
        try {
            IStatus logon = AdtLogonServiceUIFactory.createLogonServiceUI().ensureLoggedOn(
                    abapProject.getDestinationData(), PlatformUI.getWorkbench().getProgressService());
            if (!logon.isOK()) {
                appendOutput(logon.matches(IStatus.CANCEL) ? "ADT logon canceled.\n"
                        : "ADT could not authenticate the selected project. Check its connection in Project Explorer.\n");
                return false;
            }
            if (status.isDisposed() || generation != attempt) return false;
            AdtProjectClient candidate = new AdtProjectClient(project);
            boolean installed = false;
            try {
                new ProgressMonitorDialog(getSite().getShell()).run(true, true, monitor -> {
                    monitor.beginTask("Opening the selected ADT project", 1);
                    try {
                        if (monitor.isCanceled()) throw new InterruptedException();
                        candidate.login(monitor);
                        if (monitor.isCanceled()) throw new InterruptedException();
                    } catch (InterruptedException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new InvocationTargetException(e);
                    } finally {
                        monitor.done();
                    }
                });
                if (status.isDisposed() || generation != attempt) return false;
                retireClient();
                adtClient = candidate;
                selectedProject = project;
                installed = true;
                Activator.getDefault().getPreferenceStore().setValue(PreferenceInitializer.PREF_LAST_PROJECT, project.getName());
                appendOutput("Selected ABAP project " + project.getName() + " for user " + candidate.getUsername() + ".\n");
                return true;
            } finally {
                if (!installed) candidate.logout();
            }
        } catch (InterruptedException e) {
            appendOutput("Opening the ADT project was canceled.\n");
            return false;
        } catch (Exception e) {
            appendOutput("Could not open the selected ADT project. Check its connection and login in Project Explorer.\n");
            return false;
        } finally {
            selectingProject = false;
            if (!status.isDisposed()) updateControls();
        }
    }

    private void retireClient() {
        if (adtClient != null) {
            adtClient.logout();
            adtClient = null;
        }
    }

    private void checkProjectConnection() {
        if (status.isDisposed()) return;
        refreshPolicyLine();
        refreshPairingLine();
        if (!selectingProject && projectConnectionChanged()) {
            disconnectRelay();
            appendOutput("The selected ADT project was closed or its login changed. Select the ABAP project again.\n");
            updateControls();
        }
        status.getDisplay().timerExec(1000, this::checkProjectConnection);
    }

    private boolean projectConnectionChanged() {
        return selectedProject != null && !selectedProject.isAccessible()
                || adtClient != null && !adtClient.isLoggedIn();
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
        if (!prepareProject(selectedProject)) return;
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
        // Legacy calls refused by this Eclipse's encryption setting are logged with the layer that refused them.
        LegacyCalls.onRefusal(line -> {
            if (!display.isDisposed()) display.asyncExec(() -> {
                if (!status.isDisposed()) appendOutput(line + "\n");
            });
        });
        try {
            installStreams(identity);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            // The legacy path still works; only encrypted streams and pairing are unavailable.
            uninstallStreams();
            appendOutput("Encrypted streams are not available: could not prepare this Eclipse's keys.\n");
        }
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
        connected = false;
        boolean projectChanged = projectConnectionChanged();
        if (bridge != null) {
            ++generation;
            bridge.close();
            bridge = null;
        }
        uninstallStreams();
        retireClient();
        if (projectChanged) {
            selectedProject = null;
            Activator.getDefault().getPreferenceStore().setToDefault(PreferenceInitializer.PREF_LAST_PROJECT);
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
        PolicyDenials.removeListener(denialListener);
        LegacyCalls.onRefusal(null);
        E2eServices.pinStore().removeListener(pinListener);
        cancelRegistration();
        disconnectRelay();
        super.dispose();
    }

}
