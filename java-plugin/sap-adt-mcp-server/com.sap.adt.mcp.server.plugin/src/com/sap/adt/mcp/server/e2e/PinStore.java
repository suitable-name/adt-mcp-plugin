package com.sap.adt.mcp.server.e2e;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The paired desktops, keyed by the desktop's <b>inner-key fingerprint</b> (lowercase hex SHA-256 of its
 * SubjectPublicKeyInfo), which the inner handshake proves. The relay fingerprint and the label are attributes
 * only: the relay asserts them, the key proves nothing about them.
 */
public final class PinStore {
    /** One pinned desktop. {@code pairedAt} is epoch milliseconds. */
    public record Pin(String keyFingerprint, String relayFingerprint, String label, long pairedAt) {
        public Pin {
            if (!isFingerprint(keyFingerprint)) {
                throw new IllegalArgumentException("The key fingerprint must be 64 lowercase hex digits.");
            }
            relayFingerprint = relayFingerprint == null ? "" : relayFingerprint;
            label = label == null ? "" : label;
            if (relayFingerprint.length() > 128 || label.length() > MAX_LABEL) {
                throw new IllegalArgumentException("The pin attributes are too long.");
            }
        }
    }

    private static final int MAX_LABEL = 200;
    private static final int MAX_PINS = 1024;
    private static final int MAX_BYTES = 1024 * 1024;

    private final PinStorage storage;
    private final Map<String, Pin> pins = new LinkedHashMap<>();
    /** Listeners run after a change, on the changing thread, and must not call back into the store. */
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private boolean loaded;
    private IOException loadFailure;

    public PinStore(PinStorage storage) {
        this.storage = storage;
    }

    public static boolean isFingerprint(String text) {
        if (text == null || text.length() != 64) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) {
                return false;
            }
        }
        return true;
    }

    /**
     * Pins the desktop (pairedAt is now), replacing any pin with the same key fingerprint, and persists the list.
     *
     * @throws UncheckedIOException when the list cannot be read or stored; nothing changed then
     */
    public void add(String keyFingerprint, String relayFingerprint, String label) {
        try {
            add(new Pin(keyFingerprint, relayFingerprint, label, System.currentTimeMillis()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Same as {@link #add(String, String, String)} with an explicit pin. */
    public void add(Pin pin) throws IOException {
        synchronized (this) {
            load();
            if (loadFailure != null) {
                throw new IOException("The pin list could not be read; it was not changed.");
            }
            if (!pins.containsKey(pin.keyFingerprint()) && pins.size() >= MAX_PINS) {
                throw new IOException("Too many paired desktops.");
            }
            Map<String, Pin> before = new LinkedHashMap<>(pins);
            pins.put(pin.keyFingerprint(), pin);
            try {
                persist();
            } catch (IOException e) {
                pins.clear();
                pins.putAll(before);
                throw e;
            }
        }
        fire();
    }

    /** Removes the pin; returns whether there was one. */
    public boolean remove(String keyFingerprint) {
        try {
            return removeChecked(keyFingerprint);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private boolean removeChecked(String keyFingerprint) throws IOException {
        synchronized (this) {
            load();
            if (loadFailure != null) {
                throw new IOException("The pin list could not be read; it was not changed.");
            }
            Pin removed = pins.remove(keyFingerprint);
            if (removed == null) {
                return false;
            }
            try {
                persist();
            } catch (IOException e) {
                pins.put(removed.keyFingerprint(), removed);
                throw e;
            }
        }
        fire();
        return true;
    }

    /** The pin for this inner-key fingerprint. An unreadable pin list pins nothing. */
    public synchronized Optional<Pin> find(String keyFingerprint) {
        load();
        return Optional.ofNullable(pins.get(keyFingerprint));
    }

    public synchronized List<Pin> list() {
        load();
        return Collections.unmodifiableList(new ArrayList<>(pins.values()));
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    private void fire() {
        for (Runnable listener : listeners) {
            try {
                listener.run();
            } catch (RuntimeException e) {
                // A broken view must never change the pin decision.
            }
        }
    }

    private void load() {
        if (loaded) {
            return;
        }
        loaded = true;
        try {
            byte[] data = storage.read();
            if (data == null) {
                return;
            }
            if (data.length > MAX_BYTES) {
                throw new IOException("Invalid pin list.");
            }
            JsonElement root = JsonParser.parseString(new String(data, StandardCharsets.UTF_8));
            for (JsonElement element : root.getAsJsonArray()) {
                JsonObject object = element.getAsJsonObject();
                Pin pin = new Pin(object.get("key").getAsString(), object.get("relay").getAsString(),
                        object.get("label").getAsString(), object.get("pairedAt").getAsLong());
                pins.put(pin.keyFingerprint(), pin);
            }
        } catch (IOException | RuntimeException e) {
            pins.clear();
            loadFailure = e instanceof IOException io ? io : new IOException("Invalid pin list.");
        }
    }

    private void persist() throws IOException {
        JsonArray array = new JsonArray();
        for (Pin pin : pins.values()) {
            JsonObject object = new JsonObject();
            object.addProperty("key", pin.keyFingerprint());
            object.addProperty("relay", pin.relayFingerprint());
            object.addProperty("label", pin.label());
            object.addProperty("pairedAt", pin.pairedAt());
            array.add(object);
        }
        storage.write(array.toString().getBytes(StandardCharsets.UTF_8));
    }
}
