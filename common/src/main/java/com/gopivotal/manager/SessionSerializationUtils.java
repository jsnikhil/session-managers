/*
 * Copyright 2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.gopivotal.manager;

import org.apache.catalina.Manager;
import org.apache.catalina.Session;
import org.apache.catalina.session.StandardSession;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

/**
 * Utilities for serializing and deserializing {@link Session}s
 */
public final class SessionSerializationUtils {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    public static final String CIPHER_ALGORITHM = "AES";
    public static final String CIPHER_MODE = "CBC";
    public static final String CIPHER_PADDING = "PKCS5Padding";

    private static final String TRANSFORMATION = CIPHER_ALGORITHM + "/" + CIPHER_MODE + "/" + CIPHER_PADDING;
    private static final int BLOCK_SIZE = 1024;
    /**
     * **DO NOT CHANGE** - AES can use a 16-byte initialisation vector. Content is irrelevant.
     */
    private static final byte[] INITIALISATION_VECTOR = {
            'I', 'N', 'I', 'T', 'V', 'E', 'C', 'T', 'I', 'N', 'I', 'T', 'V', 'E', 'C', 'T'
    };

    private static final IvParameterSpec IVSPEC = new IvParameterSpec(INITIALISATION_VECTOR);

    Cipher cipher = null;
    private SecretKeySpec secretKey = null;

    private final Manager manager;

    /**
     * Creates a new instance
     *
     * @param manager the manager to use when recreating sessions
     */
    public SessionSerializationUtils(Manager manager) {
        this.manager = manager;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Deserialize a {@link Session}
     *
     * @param session a {@code byte[]} representing the serialized {@link Session}
     * @return the deserialized {@link Session} or {@code null} if the session data is {@code null}
     * @throws ClassNotFoundException
     * @throws IOException
     */
    public Session deserialize(byte[] session) throws ClassNotFoundException, IOException {
        if (session == null) {
            return null;
        }

        ByteArrayInputStream bytes = null;
        ObjectInputStream in = null;
        ByteArrayOutputStream cipherOStream = null;
        byte[] sessionBytes = null;

        try {
            if (secretKey != null) {
                // decrypt the bytes
                synchronized (cipher) {
                    cipherOStream = new ByteArrayOutputStream();
                    try {
                        cipher.init(Cipher.DECRYPT_MODE, secretKey, IVSPEC);
                        transform(cipher, new ByteArrayInputStream(session), cipherOStream);
                        cipherOStream.flush();
                        sessionBytes = cipherOStream.toByteArray();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

            bytes = new ByteArrayInputStream(sessionBytes == null ? session : sessionBytes);
            in = new ObjectInputStream(bytes);

            StandardSession standardSession = (StandardSession) this.manager.createEmptySession();
            standardSession.readObjectData(in);

            return standardSession;
        } finally {
            closeQuietly(in, bytes);
        }
    }

    /**
     * Serialize a {@link Session}
     *
     * @param session the {@link Session} to serialize
     * @return a {@code byte[]} representing the serialized {@link Session}
     * @throws IOException
     */
    public byte[] serialize(Session session) throws IOException {
        ByteArrayOutputStream bytesOStream = null;
        ByteArrayOutputStream cipherOStream = null;
        ObjectOutputStream out = null;
        byte[] bytes = null;

        try {
            bytesOStream = new ByteArrayOutputStream();
            out = new ObjectOutputStream(bytesOStream);

            StandardSession standardSession = (StandardSession) session;
            standardSession.writeObjectData(out);

            out.flush();
            bytesOStream.flush();

            if (secretKey != null) {
                synchronized (cipher) {
                    cipherOStream = new ByteArrayOutputStream();
                    // encrypt the byte[]
                    try {
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IVSPEC);
                        transform(cipher, new ByteArrayInputStream(bytesOStream.toByteArray()), cipherOStream);
                        cipherOStream.flush();
                        bytes = cipherOStream.toByteArray();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            if (bytes == null) {
                bytes = bytesOStream.toByteArray();
            }
            return bytes;

        } finally {
            closeQuietly(out, bytesOStream, cipherOStream);
        }

    }

    public void transform(Cipher cipher, InputStream src, OutputStream dest) throws IOException {
        CipherInputStream cis = new CipherInputStream(src, cipher);
        byte[] block = new byte[BLOCK_SIZE];
        int len;
        while ((len = cis.read(block, 0, BLOCK_SIZE)) > -1) {
            dest.write(block, 0, len);
        }
        cis.close();
    }

    public SecretKeySpec getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKeySpec secretKey) {
        this.secretKey = secretKey;
    }

    private void closeQuietly(Closeable... closeables) {
        for (Closeable closeable : closeables) {
            try {
                closeable.close();
            } catch (Exception e) {
                // Nothing to do
            }
        }
    }

}
