package com.sap.adt.mcp.sap;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLSession;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.NullProgressMonitor;

import com.sap.adt.communication.message.AdtRequestFactory;
import com.sap.adt.communication.message.ByteArrayMessageBody;
import com.sap.adt.communication.message.HeadersFactory;
import com.sap.adt.communication.message.IHeaders;
import com.sap.adt.communication.message.IRequest;
import com.sap.adt.communication.message.IResponse;
import com.sap.adt.communication.session.AdtSystemSessionFactory;
import com.sap.adt.communication.session.IStatefulSystemSession;
import com.sap.adt.destinations.logon.AdtLogonServiceFactory;
import com.sap.adt.destinations.model.ISystemConfiguration;
import com.sap.adt.tools.core.project.IAbapProject;

/** Uses an existing ADT destination and owns only the relay's stateful request session. */
public final class AdtProjectClient extends AdtRestClient {
    private static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private final IProject project;
    private final String destination;
    private final String username;
    private final String sapClient;
    private final String language;
    private final ISystemConfiguration configuration;
    private final ISystemConfiguration configurationSnapshot;
    private final AtomicReference<IStatefulSystemSession> session = new AtomicReference<>();
    private volatile boolean retired;

    public AdtProjectClient(IProject project) {
        this.project = project;
        IAbapProject abap = abapProject();
        var data = abap.getDestinationData();
        this.destination = abap.getDestinationId();
        this.username = data.getUser();
        this.sapClient = data.getClient();
        this.language = data.getLanguage();
        this.configuration = Objects.requireNonNull(data.getSystemConfiguration());
        this.configurationSnapshot = snapshotConfiguration(configuration);
    }

    private static ISystemConfiguration snapshotConfiguration(ISystemConfiguration configuration) {
        try {
            return configuration.getWritable();
        } catch (UnsupportedOperationException immutableHttpConfiguration) {
            // HTTP configurations expose no public copy API; replacement is detected by identity below.
            return null;
        }
    }

    private boolean sameConfiguration(ISystemConfiguration current) {
        return configuration == current && (configurationSnapshot == null
                || configurationSnapshot.isEquivalentTo(current)
                        && configurationSnapshot.isLoadBalancing() == current.isLoadBalancing());
    }

    private IAbapProject abapProject() {
        if (!project.isAccessible()) {
            throw new IllegalStateException("The selected ABAP project is closed or unavailable. Select the project again.");
        }
        IAbapProject abap = project.getAdapter(IAbapProject.class);
        if (abap == null) throw new IllegalStateException("Select an ABAP project.");
        return abap;
    }

    private boolean sameAuthenticatedProject() {
        if (retired || !project.isAccessible()) return false;
        IAbapProject abap = project.getAdapter(IAbapProject.class);
        if (abap == null) return false;
        var data = abap.getDestinationData();
        return destination.equals(abap.getDestinationId())
                && Objects.equals(username, data.getUser())
                && Objects.equals(sapClient, data.getClient())
                && Objects.equals(language, data.getLanguage())
                && sameConfiguration(data.getSystemConfiguration())
                && AdtLogonServiceFactory.createLogonService().isLoggedOn(destination);
    }

    @Override
    public void login() throws Exception {
        login(new NullProgressMonitor());
    }

    public void login(IProgressMonitor progress) throws Exception {
        if (!sameAuthenticatedProject()) {
            throw new IllegalStateException("Log on to the selected ABAP project using the ADT logon dialog.");
        }
        IStatefulSystemSession created = AdtSystemSessionFactory.createSystemSessionFactory()
                .createStatefulSession(destination);
        created.setDebuggingEnabled(false);
        created.setBackground(true);
        if (!session.compareAndSet(null, created)) {
            created.close();
            throw new IllegalStateException("The project session has already been prepared.");
        }
        if (retired) {
            logout();
            throw new IllegalStateException("Project selection was canceled.");
        }
        try {
            execute(IRequest.Method.GET, "/sap/bc/adt/core/discovery", null, null,
                    "application/atomsvc+xml", Map.of(), progress);
        } catch (Exception failure) {
            logout();
            throw failure;
        }
    }

    @Override
    public boolean isLoggedIn() {
        try {
            IStatefulSystemSession active = session.get();
            return active != null && active.isOpen() && sameAuthenticatedProject();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    @Override
    public String getUsername() {
        return username == null || username.isBlank() ? "ADT user" : username;
    }

    @Override
    public HttpResponse<String> get(String path, String accept) throws Exception {
        return execute(IRequest.Method.GET, path, null, null, accept, Map.of());
    }

    @Override
    public HttpResponse<String> postWithHeaders(String path, String body, String contentType,
            String accept, Map<String, String> extraHeaders) throws Exception {
        return execute(IRequest.Method.POST, path, body, contentType, accept, extraHeaders);
    }

    @Override
    public HttpResponse<String> putWithHeaders(String path, String body, String contentType,
            Map<String, String> extraHeaders) throws Exception {
        return execute(IRequest.Method.PUT, path, body, contentType, "text/plain, application/*", extraHeaders);
    }

    @Override
    public HttpResponse<String> delete(String path) throws Exception {
        return execute(IRequest.Method.DELETE, path, null, null, "*/*", Map.of());
    }

    private HttpResponse<String> execute(IRequest.Method method, String path, String body,
            String contentType, String accept, Map<String, String> extraHeaders) throws Exception {
        return execute(method, path, body, contentType, accept, extraHeaders, new NullProgressMonitor());
    }

    private HttpResponse<String> execute(IRequest.Method method, String path, String body,
            String contentType, String accept, Map<String, String> extraHeaders, IProgressMonitor progress) throws Exception {
        IStatefulSystemSession active = session.get();
        if (active == null || !active.isOpen() || !sameAuthenticatedProject() || Thread.currentThread().isInterrupted()) {
            logout();
            throw new IllegalStateException("The selected ADT session is unavailable. Select the ABAP project again.");
        }
        URI uri = URI.create(path);
        if (uri.isAbsolute() || uri.getRawAuthority() != null || uri.getRawFragment() != null
                || uri.getPath() == null || !uri.getPath().startsWith("/sap/bc/adt/")
                || uri.getPath().contains("\\")) {
            throw new IllegalArgumentException("SAP requests must use a relative ADT resource in the selected project.");
        }
        for (String segment : uri.getPath().split("/")) {
            if (segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("SAP resource paths cannot contain traversal segments.");
            }
        }
        IHeaders headers = HeadersFactory.newHeaders();
        headers.setField(HeadersFactory.newField("Accept", accept));
        if (contentType != null) headers.setField(HeadersFactory.newField("Content-Type", contentType));
        if (extraHeaders != null) {
            extraHeaders.forEach((name, value) -> headers.setField(HeadersFactory.newField(name, value)));
        }
        var messageBody = body == null ? null
                : new ByteArrayMessageBody(contentType, body.getBytes(StandardCharsets.UTF_8));
        IRequest request = AdtRequestFactory.createRequestFactory().createInstance(method, uri, headers, messageBody);
        NullProgressMonitor monitor = new NullProgressMonitor() {
            @Override
            public boolean isCanceled() {
                return retired || progress.isCanceled() || Thread.currentThread().isInterrupted() || super.isCanceled();
            }
        };
        IResponse response = active.sendRequest(monitor, request);
        String responseBody = "";
        if (response.getBody() != null) {
            try (InputStream input = response.getBody().getContent()) {
                byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES) throw new IOException("The SAP response exceeds the size limit.");
                responseBody = new String(bytes, StandardCharsets.UTF_8);
            }
        }
        if (response.getStatus() < 200 || response.getStatus() >= 300) {
            throw new IOException("SAP returned HTTP " + response.getStatus() + " for " + method
                    + ". Check the selected ADT project's connection and authorizations.");
        }
        Map<String, List<String>> fields = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        response.getHeaders().getFieldMap().forEach((name, value) -> fields.put(name, List.of(value)));
        return new ProjectResponse(response.getStatus(), HttpHeaders.of(fields, (name, value) -> true), responseBody, uri);
    }

    @Override
    public void logout() {
        retired = true;
        super.logout();
        IStatefulSystemSession previous = session.getAndSet(null);
        if (previous != null) {
            // Closing our stateful session may wait for an in-flight RFC. Never block the SWT thread.
            Thread closer = new Thread(previous::close, "SAP ADT relay session cleanup");
            closer.setDaemon(true);
            closer.start();
        }
    }

    private record ProjectResponse(int statusCode, HttpHeaders headers, String body, URI uri)
            implements HttpResponse<String> {
        @Override public HttpRequest request() { return null; }
        @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
        @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
        @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
    }
}
