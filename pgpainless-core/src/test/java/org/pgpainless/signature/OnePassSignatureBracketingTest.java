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
package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public class OnePassSignatureBracketingTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void onePassSignaturePacketsAndSignaturesAreBracketedTest(ImplementationFactory implementationFactory) throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing key1 = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        PGPSecretKeyRing key2 = PGPainless.generateKeyRing().modernKeyRing("Bob", null);
        PGPPublicKeyRing cert1 = PGPainless.extractCertificate(key1);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(cert1),
                        SigningOptions.get()
                                .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), key1, DocumentSignatureType.BINARY_DOCUMENT)
                                .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), key2, DocumentSignatureType.BINARY_DOCUMENT)
                ).setAsciiArmor(true));

        ByteArrayInputStream data = new ByteArrayInputStream("Hello, World!".getBytes(StandardCharsets.UTF_8));
        Streams.pipeAll(data, encryptionStream);
        encryptionStream.close();

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(out.toByteArray());

        InputStream inputStream = PGPUtil.getDecoderStream(ciphertextIn);
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(inputStream);

        PGPOnePassSignatureList onePassSignatures = null;
        PGPSignatureList signatures = null;

        outerloop: while (true) {
            Object next = objectFactory.nextObject();
            if (next == null) {
                break outerloop;
            }
            if (next instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) next;
                for (PGPEncryptedData encryptedData : encryptedDataList) {
                    if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                        PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                        PGPSecretKey secretKey = key1.getSecretKey(publicKeyEncryptedData.getKeyID());
                        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys());
                        PublicKeyDataDecryptorFactory decryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
                        InputStream decryptionStream = publicKeyEncryptedData.getDataStream(decryptorFactory);
                        objectFactory = new BcPGPObjectFactory(decryptionStream);
                        continue outerloop;
                    }
                }
            } else if (next instanceof PGPOnePassSignatureList) {
                onePassSignatures = (PGPOnePassSignatureList) next;
                continue outerloop;
            } else if (next instanceof PGPLiteralData) {
                continue outerloop;
            } else if (next instanceof PGPSignatureList) {
                signatures = (PGPSignatureList) next;
                continue outerloop;
            }
        }

        assertNotNull(onePassSignatures);
        assertNotNull(signatures);

        assertEquals(signatures.size(), onePassSignatures.size());
        assertEquals(2, signatures.size());

        for (int i = 0; i < signatures.size(); i++) {

            // CHECK BRACKETING

            // OnePassSignatures and Signatures are bracketed
            //  eg. (OPS1, OPS2, LiteralData, Sig2, Sig1)
            PGPOnePassSignature onePassSignature = onePassSignatures.get(i);
            PGPSignature signature = signatures.get(signatures.size() - 1 - i);
            assertEquals(onePassSignature.getKeyID(), signature.getKeyID());
            byte[] encoded = onePassSignature.getEncoded();

            // CHECK NESTED-NESS

            // 0,1 are header
            // 2 is version number
            assertEquals(3, encoded[2]);
            // 3 is sig type
            assertEquals(SignatureType.BINARY_DOCUMENT.getCode(), encoded[3]);
            // 4 is hash algo
            assertEquals(HashAlgorithm.SHA512.getAlgorithmId(), encoded[4]);
            // 5 is public key algo
            assertEquals(PublicKeyAlgorithm.EDDSA.getAlgorithmId(), encoded[5]);
            // [6,7,8,9,10,11,12,13] are key-id

            boolean last = i == signatures.size() - 1;
            // 14 is nested
            assertEquals(last ? 1 : 0, encoded[14]);
        }
    }
}
