package com.sap.adt.mcp.server;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

/** A call must match one pattern in each policy layer supplied by the authenticated relay. */
final class RelayPackageScopes {
    private static final Pattern NAME = Pattern.compile("(?:/[A-Z0-9_]+/)?[A-Z0-9_$]+");
    private static final Pattern NAMESPACE = Pattern.compile("/[A-Z0-9_]+/");
    private final List<List<String>> layers;

    private RelayPackageScopes(List<List<String>> layers) {
        this.layers = layers;
    }

    static RelayPackageScopes parse(JsonElement value) {
        if (value == null || !value.isJsonArray() || value.getAsJsonArray().size() > 2) {
            throw new IllegalArgumentException("Invalid package scope layers.");
        }
        List<List<String>> layers = new ArrayList<>();
        for (JsonElement layer : value.getAsJsonArray()) {
            if (!layer.isJsonArray() || layer.getAsJsonArray().size() > 64) {
                throw new IllegalArgumentException("Invalid package scope layer.");
            }
            JsonArray entries = layer.getAsJsonArray();
            List<String> patterns = new ArrayList<>(entries.size());
            for (JsonElement entry : entries) {
                if (!entry.isJsonPrimitive() || !entry.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException("Invalid package pattern.");
                }
                String pattern = entry.getAsString();
                boolean prefix = pattern.endsWith("*");
                String literal = prefix ? pattern.substring(0, pattern.length() - 1) : pattern;
                if (literal.length() > 30 || !(NAME.matcher(literal).matches()
                        || prefix && (literal.isEmpty() || NAMESPACE.matcher(literal).matches()))) {
                    throw new IllegalArgumentException("Invalid package pattern.");
                }
                patterns.add(pattern);
            }
            layers.add(patterns);
        }
        return new RelayPackageScopes(layers);
    }

    boolean unrestricted() {
        return layers.isEmpty();
    }

    boolean deniesAll() {
        return layers.stream().anyMatch(List::isEmpty);
    }

    boolean permits(String sapPackage) {
        if (sapPackage.isEmpty() || sapPackage.length() > 30 || !sapPackage.chars().allMatch(c -> c < 128)) {
            return false;
        }
        String name = sapPackage.toUpperCase(Locale.ROOT);
        if (!NAME.matcher(name).matches()) return false;
        for (List<String> patterns : layers) {
            if (patterns.stream().noneMatch(pattern -> pattern.endsWith("*")
                    ? name.startsWith(pattern.substring(0, pattern.length() - 1)) : name.equals(pattern))) {
                return false;
            }
        }
        return true;
    }
}
