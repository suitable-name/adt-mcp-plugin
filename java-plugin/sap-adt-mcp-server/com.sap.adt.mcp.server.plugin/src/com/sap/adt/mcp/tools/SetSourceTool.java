package com.sap.adt.mcp.tools;

import java.net.http.HttpResponse;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.sap.AdtXmlParser;

/**
 * Tool: sap_set_source -- Write ABAP source code.
 */
public class SetSourceTool extends AbstractMcpTool {

    public static final String NAME = "sap_set_source";

    public SetSourceTool(AdtRestClient client) {
        super(client);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return "Write ABAP source code to existing object. Locks, writes, unlocks, and activates automatically.";
    }

    @Override
    public JsonObject getInputSchema() {
        JsonObject sourceProp = new JsonObject();
        sourceProp.addProperty("type", "string");
        sourceProp.addProperty("description", "The complete ABAP source code to write");

        JsonObject transportProp = new JsonObject();
        transportProp.addProperty("type", "string");
        transportProp.addProperty("description", "Optional transport request number (e.g. 'DEVK900123')");

        JsonObject properties = new JsonObject();
        properties.add("objectType", AdtUrlResolver.buildTypeProperty());
        properties.add("objectName", AdtUrlResolver.buildNameProperty());
        properties.add("source", sourceProp);
        properties.add("transport", transportProp);

        JsonArray required = new JsonArray();
        required.add("objectType");
        required.add("objectName");
        required.add("source");

        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        schema.add("properties", properties);
        schema.add("required", required);

        return schema;
    }

    @Override
    public String execute(JsonObject arguments) throws Exception {
        return execute(arguments, () -> {});
    }

    @FunctionalInterface
    public interface LockedObjectCheck {
        void verify() throws Exception;
    }

    public String execute(JsonObject arguments, LockedObjectCheck afterLock) throws Exception {
        String objectUrl = AdtUrlResolver.resolveObjectUrl(optString(arguments, "objectType"), optString(arguments, "objectName"));
        if (objectUrl == null) throw new IllegalArgumentException("Provide objectType and objectName.");
        String objectSourceUrl = objectUrl + "/source/main";
        String source = arguments.get("source").getAsString();
        String transport = optString(arguments, "transport");

        if (isFunctionModuleUrl(objectSourceUrl)) {
            source = sanitizeFmSource(source);
        }

        return lockWriteUnlock(objectUrl, objectSourceUrl, source, transport,
                arguments.get("objectName").getAsString().toUpperCase(java.util.Locale.ROOT), afterLock);
    }

    private String lockWriteUnlock(String objectUrl, String sourceUrl, String source, String transport, String objectName,
            LockedObjectCheck afterLock) throws Exception {
        // Lock
        String lockPath = objectUrl + "?_action=LOCK&accessMode=MODIFY";
        HttpResponse<String> lockResp = client.postWithHeaders(lockPath, "",
                "application/*",
                "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, "
                + "application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9",
                STATEFUL_HEADERS);
        String lockHandle = AdtXmlParser.extractLockHandle(lockResp.body());

        if (lockHandle == null || lockHandle.isEmpty()) {
            throw new java.io.IOException("SAP did not return a lock handle.");
        }

        try {
            afterLock.verify();
            // Write
            String writePath = sourceUrl + "?lockHandle=" + urlEncode(lockHandle);
            if (transport != null && !transport.isEmpty()) {
                writePath = writePath + "&corrNr=" + urlEncode(transport);
            }

            HttpResponse<String> response = client.putWithHeaders(writePath, source,
                    "text/plain; charset=utf-8", STATEFUL_HEADERS);

            JsonObject output = new JsonObject();
            output.addProperty("status", "success");
            output.addProperty("statusCode", response.statusCode());

            // Activate
            String activateXml = "<adtcore:objectReferences xmlns:adtcore=\"http://www.sap.com/adt/core\">"
                    + "<adtcore:objectReference adtcore:uri=\"" + escapeXml(objectUrl)
                    + "\" adtcore:name=\"" + escapeXml(objectName) + "\"/>"
                    + "</adtcore:objectReferences>";
            HttpResponse<String> activation = client.post(
                    "/sap/bc/adt/activation?method=activate&preauditRequested=true", activateXml,
                    "application/xml", "application/xml,application/vnd.sap.adt.inactivectsobjects.v1+xml;q=0.9");
            if (activation.statusCode() != 204 && !AdtXmlParser.parseActivationResult(activation.body())
                    .get("success").getAsBoolean()) {
                throw new java.io.IOException("SAP did not confirm activation of the written source.");
            }

            output.addProperty("activated", true);

            return output.toString();
        } finally {
            String unlockPath = objectUrl + "?_action=UNLOCK&lockHandle=" + urlEncode(lockHandle);
            client.postWithHeaders(unlockPath, "", "application/*", "application/*", STATEFUL_HEADERS);
        }
    }

}
