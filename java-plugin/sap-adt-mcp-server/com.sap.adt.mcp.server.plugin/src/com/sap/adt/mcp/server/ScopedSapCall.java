package com.sap.adt.mcp.server;

import java.util.Locale;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sap.adt.mcp.sap.AdtRestClient;
import com.sap.adt.mcp.sap.AdtXmlParser;
import com.sap.adt.mcp.tools.ActivateTool;
import com.sap.adt.mcp.tools.AdtUrlResolver;
import com.sap.adt.mcp.tools.CreateObjectTool;
import com.sap.adt.mcp.tools.GetSourceTool;
import com.sap.adt.mcp.tools.LockTool;
import com.sap.adt.mcp.tools.McpTool;
import com.sap.adt.mcp.tools.ObjectStructureTool;
import com.sap.adt.mcp.tools.SearchObjectTool;
import com.sap.adt.mcp.tools.SetSourceTool;
import com.sap.adt.mcp.tools.UnlockTool;

/** Authorizes a concrete SAP target using metadata from the same logged-in ADT client that executes the call. */
final class ScopedSapCall {
    private static final Set<String> VERSIONS = Set.of("active", "inactive", "workingArea");
    private static final Set<String> TYPED_TOOLS = Set.of(GetSourceTool.NAME, ObjectStructureTool.NAME,
            LockTool.NAME, UnlockTool.NAME, SetSourceTool.NAME, ActivateTool.NAME);

    static final class Denied extends Exception {
        private static final long serialVersionUID = 1L;
        /** True when the relay's scopes allow the target and only this Eclipse's own patterns refuse it. */
        final boolean local;

        Denied() {
            this(false);
        }

        Denied(boolean local) {
            this.local = local;
        }
    }

    private final AdtRestClient sap;
    private final RelayPackageScopes relayScopes;
    private final RelayPackageScopes localScopes;

    ScopedSapCall(AdtRestClient sap, RelayPackageScopes relayScopes) {
        this(sap, relayScopes, RelayPackageScopes.NONE);
    }

    /** A target must pass the relay's scopes and, in addition, this Eclipse's own local patterns. */
    ScopedSapCall(AdtRestClient sap, RelayPackageScopes relayScopes, RelayPackageScopes localScopes) {
        this.sap = sap;
        this.relayScopes = relayScopes;
        this.localScopes = localScopes;
    }

    private boolean permits(String sapPackage) {
        return relayScopes.permits(sapPackage) && localScopes.permits(sapPackage);
    }

    private Denied deny(String sapPackage) {
        return new Denied(relayScopes.permits(sapPackage) && !localScopes.permits(sapPackage));
    }

    String execute(McpTool tool, JsonObject args) throws Exception {
        if (relayScopes.deniesAll()) throw new Denied();
        if (localScopes.deniesAll()) throw new Denied(true);
        if (tool instanceof SearchObjectTool search) return search.execute(args, this::permits);
        if (tool instanceof CreateObjectTool) {
            String destination = args.get("parentName").getAsString();
            if (!permits(destination)) throw deny(destination);
            if (!AdtUrlResolver.validObjectName(args.get("name").getAsString())) throw new Denied();
            // This is the exact destination written to the packageRef on the SAP create request.
            args.addProperty("parentName", destination.toUpperCase(Locale.ROOT));
            return tool.execute(args);
        }
        if (!TYPED_TOOLS.contains(tool.getName()) || !args.has("objectName") || !args.has("objectType")) {
            throw new Denied();
        }
        String name = args.get("objectName").getAsString();
        String family = args.get("objectType").getAsString();
        if (!AdtUrlResolver.validObjectName(name)) throw new Denied();
        String uri = AdtUrlResolver.resolveObjectUrl(family, name);
        if (uri == null) throw new Denied();
        String version = args.has("version") ? args.get("version").getAsString() : "";
        if (!version.isEmpty() && !VERSIONS.contains(version)) throw new Denied();
        String lookup = version.isEmpty() ? uri : uri + "?version=" + version;
        Metadata metadata = verify(lookup, uri, name, family);
        if (tool instanceof ObjectStructureTool) {
            // Use the same response that authorized the read.
            JsonObject structure = AdtXmlParser.parseObjectStructure(metadata.xml());
            structure.addProperty("name", name.toUpperCase(Locale.ROOT));
            structure.addProperty("packageName", metadata.owner());
            retainObjectDetails(structure, "links", "href", uri);
            retainObjectDetails(structure, "includes", "uri", uri);
            retainObjectDetails(structure, "functionModules", "uri", uri);
            return structure.toString();
        }
        if (tool instanceof SetSourceTool writer) {
            // Another SAP user may reassign a package while this session is acquiring the lock.
            return writer.execute(args, () -> verify(lookup, uri, name, family));
        }
        if (tool instanceof UnlockTool && !sap.ownsLock(args.get("lockHandle").getAsString(), uri)) {
            throw new Denied();
        }
        String output = tool.execute(args);
        if (tool instanceof GetSourceTool) {
            // Drop the source if concurrent changes have placed the object outside the grant.
            verify(lookup, uri, name, family);
        }
        return output;
    }

    private record Metadata(String xml, String owner) {}

    /** A reference to a separate object has no independent package proof in this response. */
    private static void retainObjectDetails(JsonObject structure, String field, String location, String uri) {
        if (!structure.has(field)) return;
        JsonArray own = new JsonArray();
        for (JsonElement value : structure.getAsJsonArray(field)) {
            JsonObject detail = value.getAsJsonObject();
            if (!detail.has(location) || !atOrBelow(detail.get(location).getAsString(), uri)) continue;
            if (detail.has("sourceUri") && !atOrBelow(detail.get("sourceUri").getAsString(), uri)) {
                detail.remove("sourceUri");
            }
            own.add(detail);
        }
        structure.add(field, own);
    }

    private static boolean atOrBelow(String rawPath, String uri) {
        if (!rawPath.chars().allMatch(c -> c < 128)) return false;
        String path = rawPath.toLowerCase(Locale.ROOT).replace("%24", "$").replace("%3d", "=");
        if (path.equals(uri)) return true;
        if (!path.startsWith(uri + "/")) return false;
        return path.substring(uri.length() + 1).matches("[a-z0-9_$=-]+(?:/[a-z0-9_$=-]+)*");
    }

    private Metadata verify(String lookup, String uri, String name, String family) throws Denied, InterruptedException {
        try {
            String xml = sap.get(lookup, "application/*").body();
            String owner = AdtXmlParser.verifiedPackage(xml, name, family, uri);
            if (permits(owner)) return new Metadata(xml, owner);
            throw deny(owner);
        } catch (InterruptedException | Denied e) {
            throw e;
        } catch (Exception e) {
            // Missing objects, inaccessible metadata, and unproven packages have the same external result.
        }
        throw new Denied();
    }
}
