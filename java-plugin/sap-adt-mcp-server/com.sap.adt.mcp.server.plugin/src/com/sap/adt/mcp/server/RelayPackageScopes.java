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
    /** No layers: every package passes. */
    static final RelayPackageScopes NONE = new RelayPackageScopes(List.of());
    static final int MAX_PATTERNS = 64;
    private final List<List<String>> layers;

    private RelayPackageScopes(List<List<String>> layers) {
        this.layers = layers;
    }

    /** True for an already upper-cased pattern in the relay's syntax (a name, a name prefix ending in *, or *). */
    static boolean validPattern(String pattern) {
        boolean prefix = pattern.endsWith("*");
        String literal = prefix ? pattern.substring(0, pattern.length() - 1) : pattern;
        return literal.length() <= 30 && (NAME.matcher(literal).matches()
                || prefix && (literal.isEmpty() || NAMESPACE.matcher(literal).matches()));
    }

    /** One layer built from local (not relay supplied) patterns. The caller normalises the case first. */
    static RelayPackageScopes ofLayer(List<String> patterns) {
        if (patterns.size() > MAX_PATTERNS) {
            throw new IllegalArgumentException("Invalid package scope layer.");
        }
        for (String pattern : patterns) {
            if (!validPattern(pattern)) throw new IllegalArgumentException("Invalid package pattern.");
        }
        return new RelayPackageScopes(List.of(List.copyOf(patterns)));
    }

    /** Several local layers (this Eclipse's global patterns and a desktop's own). Every layer must match. */
    static RelayPackageScopes ofLayers(List<List<String>> layers) {
        List<List<String>> copy = new ArrayList<>();
        for (List<String> layer : layers) {
            if (layer.size() > MAX_PATTERNS) throw new IllegalArgumentException("Invalid package scope layer.");
            for (String pattern : layer) {
                if (!validPattern(pattern)) throw new IllegalArgumentException("Invalid package pattern.");
            }
            copy.add(List.copyOf(layer));
        }
        return new RelayPackageScopes(List.copyOf(copy));
    }

    static RelayPackageScopes parse(JsonElement value) {
        if (value == null || !value.isJsonArray() || value.getAsJsonArray().size() > 2) {
            throw new IllegalArgumentException("Invalid package scope layers.");
        }
        List<List<String>> layers = new ArrayList<>();
        for (JsonElement layer : value.getAsJsonArray()) {
            if (!layer.isJsonArray() || layer.getAsJsonArray().size() > MAX_PATTERNS) {
                throw new IllegalArgumentException("Invalid package scope layer.");
            }
            JsonArray entries = layer.getAsJsonArray();
            List<String> patterns = new ArrayList<>(entries.size());
            for (JsonElement entry : entries) {
                if (!entry.isJsonPrimitive() || !entry.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException("Invalid package pattern.");
                }
                String pattern = entry.getAsString();
                if (!validPattern(pattern)) {
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
