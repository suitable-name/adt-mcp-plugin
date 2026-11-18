package com.sap.adt.mcp.server;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.equinox.security.storage.ISecurePreferences;
import org.eclipse.equinox.security.storage.SecurePreferencesFactory;
import org.eclipse.equinox.security.storage.StorageException;

import com.google.gson.JsonParser;
import com.sap.adt.mcp.Activator;

/** One atomically replaced, encrypted identity per Eclipse workspace. */
public final class RelayProfileStore {
    private static final int NONCE_BYTES = 12;
    private static final int MAX_BYTES = 128 * 1024;
    private final Path path = Activator.getDefault().getStateLocation().toFile().toPath().resolve("relay-profile.enc");

    public boolean exists() {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
    }

    public RelayIdentity load() throws GeneralSecurityException, StorageException, IOException {
        byte[] data;
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            data = input.readNBytes(MAX_BYTES + 1);
        }
        if (data.length <= NONCE_BYTES || data.length > MAX_BYTES) {
            throw new IOException("Invalid relay profile.");
        }
        Cipher decrypt = cipher(Cipher.DECRYPT_MODE, Arrays.copyOf(data, NONCE_BYTES));
        byte[] clear = decrypt.doFinal(data, NONCE_BYTES, data.length - NONCE_BYTES);
        try {
            return RelayIdentity.fromProfile(JsonParser.parseString(new String(clear, StandardCharsets.UTF_8))
                    .getAsJsonObject());
        } finally {
            Arrays.fill(clear, (byte) 0);
        }
    }

    public void save(RelayIdentity identity) throws GeneralSecurityException, StorageException, IOException {
        byte[] nonce = new byte[NONCE_BYTES];
        new SecureRandom().nextBytes(nonce);
        Cipher encrypt = cipher(Cipher.ENCRYPT_MODE, nonce);
        byte[] clear = identity.profile().toString().getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext;
        try {
            ciphertext = encrypt.doFinal(clear);
        } finally {
            Arrays.fill(clear, (byte) 0);
        }
        Path temporary = Files.createTempFile(path.getParent(), "relay-profile-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer contents = ByteBuffer.allocate(nonce.length + ciphertext.length);
                contents.put(nonce).put(ciphertext).flip();
                while (contents.hasRemaining()) {
                    channel.write(contents);
                }
                channel.force(true);
            }
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private Cipher cipher(int mode, byte[] nonce) throws GeneralSecurityException, StorageException, IOException {
        ISecurePreferences vault = SecurePreferencesFactory.getDefault().node(Activator.PLUGIN_ID);
        byte[] workspace = path.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8);
        String keyName = "relayProfileKey-" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(workspace));
        byte[] wrappingKey;
        // Across plugins in this Eclipse process the secure preference store has one shared namespace.
        synchronized (RelayProfileStore.class) {
            wrappingKey = vault.getByteArray(keyName, null);
            if (wrappingKey == null) {
                if (mode == Cipher.DECRYPT_MODE) {
                    throw new GeneralSecurityException("Missing secure storage key.");
                }
                wrappingKey = new byte[32];
                new SecureRandom().nextBytes(wrappingKey);
                vault.putByteArray(keyName, wrappingKey, true);
                vault.flush();
            }
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(wrappingKey, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(workspace);
            return cipher;
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
        }
    }
}
