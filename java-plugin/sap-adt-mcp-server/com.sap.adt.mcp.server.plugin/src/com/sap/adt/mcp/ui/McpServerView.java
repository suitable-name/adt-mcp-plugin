package com.sap.adt.mcp.ui;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.InputDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.SWT;
import org.eclipse.swt.SWTException;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.dialogs.ElementListSelectionDialog;
import org.eclipse.ui.part.ViewPart;

import com.sap.adt.destinations.ui.logon.AdtLogonServiceUIFactory;
import com.sap.adt.mcp.Activator;
import com.sap.adt.mcp.preferences.PreferenceInitializer;
import com.sap.adt.mcp.sap.AdtProjectClient;
import com.sap.adt.mcp.server.RelayBridge;
import com.sap.adt.mcp.server.RelayEnrollment;
import com.sap.adt.mcp.server.RelayIdentity;
import com.sap.adt.mcp.server.RelayProfileStore;
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
    private Button registerButton;
    private Button sapButton;
    private Button bridgeButton;
    private StyledText outputText;

    @Override
    public void createPartControl(Composite parent) {
        parent.setLayout(new GridLayout(1, false));
        status = new Label(parent, SWT.WRAP);
        status.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        Composite actions = new Composite(parent, SWT.NONE);
        actions.setLayout(new RowLayout(SWT.HORIZONTAL));
        actions.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));
        registerButton = button(actions, "Register Eclipse", this::register);
        sapButton = button(actions, "Select ABAP Project", this::selectProject);
        bridgeButton = button(actions, "Connect Relay", this::toggleRelay);

        outputText = new StyledText(parent, SWT.BORDER | SWT.MULTI | SWT.V_SCROLL | SWT.H_SCROLL);
        outputText.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
        outputText.setEditable(false);
        button(actions, "Clear", () -> outputText.setText(""));
        restoreSelectedProject();
        updateControls();
        parent.getDisplay().timerExec(1000, this::checkProjectConnection);
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
        cancelRegistration();
        disconnectRelay();
        super.dispose();
    }

}
