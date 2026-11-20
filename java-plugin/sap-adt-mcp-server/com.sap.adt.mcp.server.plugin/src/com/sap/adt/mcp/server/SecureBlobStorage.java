package com.sap.adt.mcp.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

import org.eclipse.equinox.security.storage.ISecurePreferences;
import org.eclipse.equinox.security.storage.SecurePreferencesFactory;
import org.eclipse.equinox.security.storage.StorageException;

import com.sap.adt.mcp.Activator;
/**
 * One named blob in Eclipse secure storage, scoped to this workspace, as {@link RelayProfileStore} scopes the relay
 * identity. Backs the inner identity key and the pin list. The activator installs it with
 * {@link E2eServices#useStorage}; {@link E2eServices} itself has no Eclipse types.
 */
public final class SecureBlobStorage implements E2eServices.Storage {
    private static final int MAX_BYTES = 1024 * 1024;
    private final String name;

    public SecureBlobStorage(String name) {
        this.name = name;
    }

    @Override
    public byte[] read() throws IOException {
        // Across plugins in this Eclipse process the secure preference store has one shared namespace.
        synchronized (SecureBlobStorage.class) {
            try {
                byte[] blob = node().getByteArray(keyName(), null);
                if (blob != null && blob.length > MAX_BYTES) {
                    throw new IOException("Invalid stored data.");
                }
                return blob;
            } catch (StorageException | GeneralSecurityException e) {
                throw new IOException("Secure storage could not be read.");
            }
        }
    }

    @Override
    public void write(byte[] blob) throws IOException {
        synchronized (SecureBlobStorage.class) {
            try {
                ISecurePreferences node = node();
                node.putByteArray(keyName(), blob, true);
                node.flush();
            } catch (StorageException | GeneralSecurityException e) {
                throw new IOException("Secure storage could not be written.");
            }
        }
    }

    private static ISecurePreferences node() {
        return SecurePreferencesFactory.getDefault().node(Activator.PLUGIN_ID);
    }

    private String keyName() throws GeneralSecurityException {
        byte[] workspace = Activator.getDefault().getStateLocation().toFile().toPath().toAbsolutePath().normalize()
                .toString().getBytes(StandardCharsets.UTF_8);
        return name + "-" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(workspace));
    }
}
