package com.sap.adt.mcp.tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The shared tool table (resources/tools.json), the same file the relay embeds.
 * Lists every tool with its action class, package awareness and component actions.
 */
public final class ToolCatalog {

    private static final String RESOURCE = "/resources/tools.json";
    private static volatile ToolCatalog bundled;

    private final Map<String, Entry> entries;

    private ToolCatalog(Map<String, Entry> entries) {
        this.entries = entries;
    }

    private record Entry(ToolClass toolClass, boolean packageAware, List<String> components) {
    }

    /** Loads the table bundled with the plugin; parsed once. */
    public static ToolCatalog bundled() {
        ToolCatalog catalog = bundled;
        if (catalog == null) {
            synchronized (ToolCatalog.class) {
                catalog = bundled;
                if (catalog == null) {
                    try (InputStream stream = ToolCatalog.class.getResourceAsStream(RESOURCE)) {
                        if (stream == null) {
                            throw new IllegalStateException("Missing bundled resource " + RESOURCE);
                        }
                        catalog = load(new InputStreamReader(stream, StandardCharsets.UTF_8));
                    } catch (IOException e) {
                        throw new IllegalStateException("Cannot read " + RESOURCE, e);
                    }
                    bundled = catalog;
                }
            }
        }
        return catalog;
    }

    /** Parses a table. Throws {@link IllegalStateException} when it is malformed. */
    public static ToolCatalog load(Reader reader) {
        JsonObject root;
        try {
            root = JsonParser.parseReader(reader).getAsJsonObject();
        } catch (RuntimeException e) {
            throw new IllegalStateException("tools.json is not a valid JSON object", e);
        }
        if (!root.has("version") || root.get("version").getAsInt() != 1) {
            throw new IllegalStateException("tools.json has an unsupported version");
        }
        JsonArray tools = root.getAsJsonArray("tools");
        if (tools == null) {
            throw new IllegalStateException("tools.json has no tools array");
        }
        Map<String, Entry> entries = new LinkedHashMap<>();
        for (JsonElement element : tools) {
            JsonObject tool = element.getAsJsonObject();
            String name = tool.get("name").getAsString();
            ToolClass toolClass = ToolClass.parse(tool.get("class").getAsString())
                    .orElseThrow(() -> new IllegalStateException("tools.json: invalid class for " + name));
            List<String> components = new ArrayList<>();
            for (JsonElement component : tool.getAsJsonArray("components")) {
                components.add(component.getAsString());
            }
            Entry entry = new Entry(toolClass, tool.get("packageAware").getAsBoolean(),
                    Collections.unmodifiableList(components));
            if (entries.put(name, entry) != null) {
                throw new IllegalStateException("tools.json: duplicate tool " + name);
            }
        }
        for (Map.Entry<String, Entry> item : entries.entrySet()) {
            for (String component : item.getValue().components()) {
                if (!entries.containsKey(component)) {
                    throw new IllegalStateException(
                            "tools.json: " + item.getKey() + " lists unknown component " + component);
                }
            }
        }
        return new ToolCatalog(Collections.unmodifiableMap(entries));
    }

    public Optional<ToolClass> classOf(String tool) {
        return Optional.ofNullable(entries.get(tool)).map(Entry::toolClass);
    }

    public boolean packageAware(String tool) {
        Entry entry = entries.get(tool);
        return entry != null && entry.packageAware();
    }

    public List<String> components(String tool) {
        Entry entry = entries.get(tool);
        return entry == null ? List.of() : entry.components();
    }

    public Set<String> names() {
        return entries.keySet();
    }

    /**
     * Fails when a registered tool is missing from the bundled table or declares another class.
     *
     * @throws IllegalStateException naming the first offending tool
     */
    public static void verify(Collection<McpTool> tools) {
        bundled().verifyAgainst(tools);
    }

    /** Same check against this table. */
    public void verifyAgainst(Collection<McpTool> tools) {
        for (McpTool tool : tools) {
            Optional<ToolClass> listed = classOf(tool.getName());
            if (listed.isEmpty()) {
                throw new IllegalStateException("Tool " + tool.getName() + " is missing from tools.json");
            }
            if (listed.get() != tool.toolClass()) {
                throw new IllegalStateException("Tool " + tool.getName() + " is class " + tool.toolClass()
                        + " in code but " + listed.get() + " in tools.json");
            }
        }
    }
}
