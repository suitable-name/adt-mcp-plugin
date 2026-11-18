package com.sap.adt.mcp.sap;

import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SAP operations used by the relay's tools. Implementations obtain transport and
 * authentication from the selected ADT project.
 */
public abstract class AdtRestClient {
    public static final String SESSION_TYPE_HEADER = "X-sap-adt-sessiontype";

    private final Map<String, String> explicitLocks = new ConcurrentHashMap<>();

    protected AdtRestClient() {
    }

    public void requireLockCapacity() {
        if (explicitLocks.size() >= 4096) throw new IllegalStateException("Too many open SAP locks.");
    }

    public void rememberLock(String handle, String objectUri) {
        explicitLocks.put(handle, objectUri);
    }

    public boolean ownsLock(String handle, String objectUri) {
        return objectUri.equals(explicitLocks.get(handle));
    }

    public void forgetLock(String handle, String objectUri) {
        explicitLocks.remove(handle, objectUri);
    }

    /** Establish access using the selected project's ADT authentication flow. */
    public abstract void login() throws Exception;

    public abstract boolean isLoggedIn();

    public abstract String getUsername();

    public abstract HttpResponse<String> get(String path, String accept) throws Exception;

    public HttpResponse<String> post(String path, String body, String contentType, String accept)
            throws Exception {
        return postWithHeaders(path, body, contentType, accept, Map.of());
    }

    public abstract HttpResponse<String> postWithHeaders(String path, String body,
            String contentType, String accept, Map<String, String> extraHeaders) throws Exception;

    public HttpResponse<String> put(String path, String body, String contentType) throws Exception {
        return putWithHeaders(path, body, contentType, Map.of());
    }

    public abstract HttpResponse<String> putWithHeaders(String path, String body,
            String contentType, Map<String, String> extraHeaders) throws Exception;

    public abstract HttpResponse<String> delete(String path) throws Exception;

    /**
     * Release this relay client's state without logging the shared ADT project
     * out of SAP. Implementations also retire their local transport binding.
     */
    public void logout() {
        explicitLocks.clear();
    }
}
