/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.selection.key.impl.SignatureKeySelectionStrategy;

public class SigningTest {

    @Test
    public void testEncryptionAndSignatureVerification() throws IOException, PGPException {

        PGPPublicKeyRing julietKeys = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRing romeoKeys = TestKeys.getRomeoPublicKeyRing();

        PGPSecretKeyRing cryptieKeys = TestKeys.getCryptieSecretKeyRing();
        PGPSecretKey cryptieSigningKey = new SignatureKeySelectionStrategy()
                .selectKeysFromKeyRing(cryptieKeys)
                .iterator().next();

        PGPPublicKeyRingCollection keys = new PGPPublicKeyRingCollection(Arrays.asList(julietKeys, romeoKeys));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign(EncryptionStream.Purpose.STORAGE)
                .onOutputStream(out)
                .toRecipients(keys)
                .andToSelf(KeyRingUtils.publicKeyRingFrom(cryptieKeys))
                .usingAlgorithms(SymmetricKeyAlgorithm.AES_192, HashAlgorithm.SHA384, CompressionAlgorithm.ZIP)
                .signWith(SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, cryptieSigningKey), cryptieSigningKey)
                .signCanonicalText()
                .asciiArmor();

        byte[] messageBytes = "This message is signed and encrypted to Romeo and Juliet.".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream message = new ByteArrayInputStream(messageBytes);

        Streams.pipeAll(message, encryptionStream);
        encryptionStream.close();

        byte[] encrypted = out.toByteArray();
        ByteArrayInputStream cryptIn = new ByteArrayInputStream(encrypted);

        PGPSecretKeyRing romeoSecret = TestKeys.getRomeoSecretKeyRing();
        PGPSecretKeyRing julietSecret = TestKeys.getJulietSecretKeyRing();

        PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(Arrays.asList(romeoSecret, julietSecret));
        Set<OpenPgpV4Fingerprint> trustedFingerprints = new HashSet<>();
        trustedFingerprints.add(new OpenPgpV4Fingerprint(cryptieKeys));
        trustedFingerprints.add(new OpenPgpV4Fingerprint(julietKeys));
        PGPPublicKeyRingCollection verificationKeys = new PGPPublicKeyRingCollection(Arrays.asList(KeyRingUtils.publicKeyRingFrom(cryptieKeys), romeoKeys));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify().onInputStream(cryptIn)
                .decryptWith(secretKeys)
                .verifyWith(trustedFingerprints, verificationKeys)
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertEquals(SymmetricKeyAlgorithm.AES_192, metadata.getSymmetricKeyAlgorithm());
        assertEquals(HashAlgorithm.SHA384.getAlgorithmId(), metadata.getSignatures().iterator().next().getHashAlgorithm());
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isSigned());
        assertTrue(metadata.isVerified());
        assertTrue(metadata.isIntegrityProtected());
        assertTrue(metadata.containsVerifiedSignatureFrom(KeyRingUtils.publicKeyRingFrom(cryptieKeys)));
        assertFalse(metadata.containsVerifiedSignatureFrom(julietKeys));
    }
}
