package com.sap.adt.mcp.tools;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonObject;

/**
 * Source-level regression harness for the shared tool table. Run with the path of tools.json as the
 * only argument. The tools are built with a null SAP client, which their constructors only store.
 */
public final class ToolCatalogRegression {

    public static void main(String[] args) throws IOException {
        check(args.length == 1, "Pass the path of tools.json as the only argument.");
        ToolCatalog catalog;
        try (Reader reader = Files.newBufferedReader(Path.of(args[0]), StandardCharsets.UTF_8)) {
            catalog = ToolCatalog.load(reader);
        }
        List<McpTool> tools = List.of(new AbapDocuTool(null), new ActivateTool(null), new AtcRunTool(null),
                new CreateObjectTool(null), new GetSourceTool(null), new InactiveObjectsTool(null),
                new LockTool(null), new ObjectStructureTool(null), new RunUnitTestTool(null),
                new SearchObjectTool(null), new SetSourceTool(null), new SqlQueryTool(null),
                new SyntaxCheckTool(null), new UnlockTool(null), new UsageReferencesTool(null));
        check(tools.size() == 15, "Expected 15 tools.");

        // Every implementation is listed with the class it declares, and every listed tool is implemented.
        catalog.verifyAgainst(tools);
        List<String> implemented = new ArrayList<>();
        for (McpTool tool : tools) {
            implemented.add(tool.getName());
            check(catalog.classOf(tool.getName()).orElseThrow() == tool.toolClass(),
                    "Class differs for " + tool.getName());
        }
        check(catalog.names().equals(Set.copyOf(implemented)) && catalog.names().size() == implemented.size(),
                "tools.json and the implementations list different tools.");

        // The classes and flags the relay policy relies on.
        Map<String, ToolClass> expected = Map.ofEntries(
                Map.entry("sap_abap_docu", ToolClass.READ), Map.entry("sap_get_source", ToolClass.READ),
                Map.entry("sap_inactive_objects", ToolClass.READ), Map.entry("sap_object_structure", ToolClass.READ),
                Map.entry("sap_search_object", ToolClass.READ), Map.entry("sap_usage_references", ToolClass.READ),
                Map.entry("sap_activate", ToolClass.WRITE), Map.entry("sap_create_object", ToolClass.WRITE),
                Map.entry("sap_lock", ToolClass.WRITE), Map.entry("sap_set_source", ToolClass.WRITE),
                Map.entry("sap_unlock", ToolClass.WRITE), Map.entry("sap_atc_run", ToolClass.EXECUTE),
                Map.entry("sap_run_unit_test", ToolClass.EXECUTE), Map.entry("sap_sql_query", ToolClass.EXECUTE),
                Map.entry("sap_syntax_check", ToolClass.EXECUTE));
        for (Map.Entry<String, ToolClass> entry : expected.entrySet()) {
            check(catalog.classOf(entry.getKey()).orElseThrow() == entry.getValue(), "Table class " + entry.getKey());
        }
        Set<String> packageAware = Set.of("sap_activate", "sap_create_object", "sap_get_source", "sap_lock",
                "sap_object_structure", "sap_search_object", "sap_set_source", "sap_unlock");
        for (String name : catalog.names()) {
            check(catalog.packageAware(name) == packageAware.contains(name), "Package awareness of " + name);
            check(catalog.components(name).equals(name.equals("sap_set_source")
                    ? List.of("sap_lock", "sap_unlock", "sap_activate") : List.of()), "Components of " + name);
        }
        check(catalog.classOf("sap_unknown").isEmpty() && !catalog.packageAware("sap_unknown")
                && catalog.components("sap_unknown").isEmpty(), "Unknown tools must not be listed.");

        // verify() rejects a tool whose class differs or that is not listed, naming the tool.
        McpTool wrongClass = new Relabelled(new GetSourceTool(null), "sap_get_source", ToolClass.WRITE);
        rejects(catalog, wrongClass, "sap_get_source");
        McpTool unlisted = new Relabelled(new GetSourceTool(null), "sap_new_tool", ToolClass.READ);
        rejects(catalog, unlisted, "sap_new_tool");
        List<McpTool> mixed = new ArrayList<>(tools);
        mixed.add(1, wrongClass);
        try {
            catalog.verifyAgainst(mixed);
            throw new AssertionError("verify accepted a mismatching tool.");
        } catch (IllegalStateException e) {
            check(e.getMessage().contains("sap_get_source"), "verify must name the first offending tool.");
        }

        // The bundled table (classpath resource) is the same table.
        check(ToolCatalog.bundled().names().equals(catalog.names()),
                "The bundled /resources/tools.json differs from " + args[0]);
        ToolCatalog.verify(tools);
    }

    private static void rejects(ToolCatalog catalog, McpTool tool, String name) {
        try {
            catalog.verifyAgainst(List.of(tool));
        } catch (IllegalStateException e) {
            check(e.getMessage().contains(name), "The error must name " + name + ".");
            return;
        }
        throw new AssertionError("verify accepted " + name + " with the wrong class or name.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /** Delegates to a real tool but reports another name and class. */
    private static final class Relabelled implements McpTool {
        private final McpTool inner;
        private final String name;
        private final ToolClass toolClass;

        Relabelled(McpTool inner, String name, ToolClass toolClass) {
            this.inner = inner;
            this.name = name;
            this.toolClass = toolClass;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public ToolClass toolClass() {
            return toolClass;
        }

        @Override
        public String getDescription() {
            return inner.getDescription();
        }

        @Override
        public JsonObject getInputSchema() {
            return inner.getInputSchema();
        }

        @Override
        public String execute(JsonObject arguments) throws Exception {
            return inner.execute(arguments);
        }
    }
}
