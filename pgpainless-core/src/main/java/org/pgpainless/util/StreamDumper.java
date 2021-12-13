// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.subpackets.KeyServerPreferences;

public class StreamDumper {

    public static void main(String[] args) throws PGPException, IOException {
        if (args.length == 0) {
            dump(System.in, null, System.out);
        } else if (args.length == 1) {
            PGPSessionKey sessionKey = PGPSessionKey.fromAsciiRepresentation(args[0]);
            dump(System.in, sessionKey, System.out);
        } else {
            // CHECKSTYLE:OFF
            System.err.println("Usage: StreamDumper [session-key]");
            // CHECKSTYLE:ON
        }

    }

    public static void dump(InputStream inputStream, PGPSessionKey sessionKey, OutputStream outputStream) throws IOException, PGPException {
        PrintWriter printWriter = new PrintWriter(outputStream);
        PrintWriterWrapper pww = new PrintWriterWrapper(printWriter);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(inputStream);
        walkObjects(pww, objectFactory, sessionKey);
        printWriter.flush();
    }

    private static void walkObjects(PrintWriterWrapper pww, PGPObjectFactory objectFactory, PGPSessionKey sessionKey) throws IOException, PGPException {
        Object next;

        while ((next = objectFactory.nextObject()) != null) {

            if (next instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) next;
                Iterator<PGPOnePassSignature> iterator = onePassSignatures.iterator();
                while (iterator.hasNext()) {
                    PGPOnePassSignature pgpOnePassSignature = iterator.next();
                    pww.appendLine("One-Pass Signature Packet").iind()
                            .appendLine("Type: " + SignatureType.valueOf(pgpOnePassSignature.getSignatureType()))
                            .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(pgpOnePassSignature.getKeyAlgorithm()))
                            .appendLine("Hash Algorithm: " + HashAlgorithm.fromId(pgpOnePassSignature.getHashAlgorithm()))
                            .appendLine("Issuer Key ID: " + Long.toHexString(pgpOnePassSignature.getKeyID()))
                            .dind()
                            .emptyLine();
                }
            }

            else if (next instanceof PGPSignatureList) {
                PGPSignatureList signatures = (PGPSignatureList) next;
                for (PGPSignature signature : signatures) {
                    appendSignature(pww, signature);
                    pww.emptyLine();
                }
            }

            else if (next instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) next;
                SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory = null;
                if (sessionKey != null) {
                    sessionKeyDataDecryptorFactory = new BcSessionKeyDataDecryptorFactory(sessionKey);
                }
                for (PGPEncryptedData encryptedData : encryptedDataList) {

                    boolean decrypted = false;
                    if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                        PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) encryptedData;
                        pww.appendLine("Public-Key Encrypted Session Key Packet").iind()
                                .appendLine("Recipient: " + Long.toHexString(pkesk.getKeyID()));

                        if (sessionKeyDataDecryptorFactory != null) {
                            try {
                                InputStream inputStream = pkesk.getDataStream(sessionKeyDataDecryptorFactory);
                                pww.appendLine("Session Key: " + Hex.toHexString(sessionKey.getKey()));
                                pww.appendLine("Symmetric Algorithm: " + SymmetricKeyAlgorithm.fromId(sessionKey.getAlgorithm()));
                                pww.appendLine("Decryption Successful");
                                pww.emptyLine();

                                PGPObjectFactory decryptedFactory = new BcPGPObjectFactory(inputStream);
                                walkObjects(pww, decryptedFactory, sessionKey);
                                decrypted = true;
                            } catch (PGPException | IOException e) {
                                pww.appendLine("Decryption Failed")
                                        .emptyLine();
                            }
                        } else {
                            pww.appendLine("No Decryption Method")
                                    .emptyLine();
                        }

                        if (pkesk.isIntegrityProtected()) {
                            pww.appendLine("Modification Detection Code Packet").iind();
                            if (decrypted) {
                                pww.appendLine("Valid: " + pkesk.verify());
                            }
                        }
                        pww.dind();
                    }

                    else if (encryptedData instanceof PGPPBEEncryptedData) {
                        PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) encryptedData;
                        pww.appendLine("Symmetric-Key Encrypted Session Key Packet").iind()
                                .appendLine("Integrity Protected: " + skesk.isIntegrityProtected())
                                .dind().emptyLine();

                        if (sessionKeyDataDecryptorFactory != null) {
                            try {
                                InputStream inputStream = skesk.getDataStream(sessionKeyDataDecryptorFactory);
                                pww.appendLine("Session Key: " + Hex.toHexString(sessionKey.getKey()));
                                pww.appendLine("Symmetric Algorithm: " + SymmetricKeyAlgorithm.fromId(sessionKey.getAlgorithm()));
                                pww.appendLine("Decryption Successful");
                                pww.emptyLine();

                                PGPObjectFactory decryptedFactory = new BcPGPObjectFactory(inputStream);
                                walkObjects(pww, decryptedFactory, sessionKey);
                                decrypted = true;
                            } catch (PGPException | IOException e) {
                                pww.appendLine("Decryption Failed");
                            }
                        } else {
                            pww.appendLine("No Decryption Method")
                                    .emptyLine();
                        }

                        if (skesk.isIntegrityProtected()) {
                            pww.appendLine("Modification Detection Code Packet").iind();
                            if (decrypted) {
                                pww.appendLine("Valid: " + skesk.verify());
                            }
                        }
                        pww.dind();
                    }

                    pww.dind().emptyLine();
                }
                pww.emptyLine();
            }

            else if (next instanceof PGPLiteralData) {
                PGPLiteralData literalData = (PGPLiteralData) next;
                StreamEncoding encoding = StreamEncoding.fromCode(literalData.getFormat());
                String fileName = literalData.getFileName();
                Date modificationDate = literalData.getModificationTime();

                pww.appendLine("Literal Data Packet").iind()
                        .appendLine("Format: " + encoding);
                if (fileName != null && !fileName.isEmpty()) {
                    pww.appendLine("File Name: " + fileName);
                }
                if (modificationDate != null && modificationDate.getTime() != 0) {
                    pww.appendLine("Modification Date: " + DateUtil.formatUTCDate(modificationDate));
                }

                byte[] peek = new byte[512];
                InputStream literalIn = literalData.getDataStream();
                int read = literalIn.read(peek);
                Streams.drain(literalIn);
                literalIn.close();

                String content = "";
                if (read != -1) {
                    content = new String(peek, 0, read).replace("\r", "\\r").replace("\n", "\\n");
                }
                pww.appendLine("Content: \"" + content + "\"")
                        .dind()
                        .emptyLine();
            }

            else if (next instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) next;
                pww.appendLine("Compressed Data Packet").iind()
                        .appendLine("Algorithm: " + CompressionAlgorithm.fromId(compressedData.getAlgorithm()))
                        .emptyLine();

                PGPObjectFactory compressedFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                walkObjects(pww, compressedFactory, sessionKey);
                pww.dind();
            }

            else if (next instanceof PGPMarker) {
                pww.appendLine("Marker Packet")
                        .emptyLine();
            }

            else if (next instanceof PGPSecretKeyRing) {
                PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) next;

                for (PGPSecretKey secretKey : secretKeys) {
                    appendSecretKey(pww, secretKey);
                }

                for (Iterator<PGPPublicKey> it = secretKeys.getExtraPublicKeys(); it.hasNext(); ) {
                    PGPPublicKey publicKey = it.next();
                    appendPublicKey(pww, publicKey);
                }
            }

            else if (next instanceof PGPPublicKeyRing) {
                PGPPublicKeyRing publicKeys = (PGPPublicKeyRing) next;
                for (PGPPublicKey publicKey : publicKeys) {
                    appendPublicKey(pww, publicKey);
                }
            }

            else if (next instanceof PGPPublicKey) {
                appendPublicKey(pww, (PGPPublicKey) next);
            }

            else if (next instanceof Packet) {
                Packet packet = (Packet) next;
                pww.appendLine("Experimental Packet: " + packet.toString());
            }
            /*

            case PacketTags.SYMMETRIC_KEY_ENC_SESSION:
            case PacketTags.ONE_PASS_SIGNATURE:
            case PacketTags.SECRET_KEY:
            case PacketTags.PUBLIC_KEY:
            case PacketTags.SECRET_SUBKEY:
            case PacketTags.COMPRESSED_DATA:
            case PacketTags.SYMMETRIC_KEY_ENC:
            case PacketTags.MARKER:
            case PacketTags.LITERAL_DATA:
            case PacketTags.TRUST:
            case PacketTags.USER_ID:
            case PacketTags.PUBLIC_SUBKEY:
            case PacketTags.USER_ATTRIBUTE:
            case PacketTags.SYM_ENC_INTEGRITY_PRO:
            case PacketTags.MOD_DETECTION_CODE:

            case PacketTags.EXPERIMENTAL_1:
            case PacketTags.EXPERIMENTAL_2:
            case PacketTags.EXPERIMENTAL_3:
            case PacketTags.EXPERIMENTAL_4:
             */
        }
    }

    private static void appendSecretKey(PrintWriterWrapper pww, PGPSecretKey secretKey) throws PGPException {
        PGPPublicKey publicKey = secretKey.getPublicKey();
        pww.appendLine(publicKey.isMasterKey() ? "Secret-Key Packet" : "Secret-Subkey Packet").iind()
                .appendLine("Version: " + publicKey.getVersion())
                .appendLine("Creation Time: " + DateUtil.formatUTCDate(publicKey.getCreationTime()))
                .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(publicKey.getAlgorithm()))
                .appendLine("Public Key Size: " + publicKey.getBitStrength())
                .appendLine("Fingerprint: " + Hex.toHexString(publicKey.getFingerprint()))
                .appendLine("Key-ID: " + Long.toHexString(publicKey.getKeyID()))
                .dind().emptyLine();

        appendPublicKeyAppendix(pww, publicKey);
    }

    private static void appendPublicKey(PrintWriterWrapper pww, PGPPublicKey publicKey) throws PGPException {
        pww.appendLine(publicKey.isMasterKey() ? "Public-Key Packet" : "Public-Subkey Packet").iind()
                .appendLine("Version: " + publicKey.getVersion())
                .appendLine("Creation Time: " + DateUtil.formatUTCDate(publicKey.getCreationTime()))
                .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(publicKey.getAlgorithm()))
                .appendLine("Public Key Size: " + publicKey.getBitStrength())
                .appendLine("Fingerprint: " + Hex.toHexString(publicKey.getFingerprint()))
                .appendLine("Key-ID: " + Long.toHexString(publicKey.getKeyID()))
                .dind().emptyLine();

        appendPublicKeyAppendix(pww, publicKey);
    }

    private static void appendPublicKeyAppendix(PrintWriterWrapper pww, PGPPublicKey publicKey) throws PGPException {
        List<PGPSignature> allSignatures = CollectionUtils.iteratorToList(publicKey.getSignatures());
        List<PGPSignature> directKeySignatures = CollectionUtils.iteratorToList(publicKey.getSignaturesOfType(SignatureType.DIRECT_KEY.getCode()));

        for (PGPSignature signature : directKeySignatures) {
            allSignatures.remove(signature);
            appendSignature(pww, signature);
            pww.emptyLine();
        }

        for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            pww.appendLine("User-ID Packet").iind()
                    .appendLine("Value: " + userId)
                    .dind().emptyLine();

            List<PGPSignature> userIdSigs = CollectionUtils.iteratorToList(publicKey.getSignaturesForID(userId));
            for (PGPSignature signature :  userIdSigs) {
                appendSignature(pww, signature);
                allSignatures.remove(signature);
                pww.emptyLine();
            }
        }

        for (PGPSignature signature : allSignatures) {
            appendSignature(pww, signature);
            pww.emptyLine();
        }
    }

    private static void appendSignature(PrintWriterWrapper pww, PGPSignature signature) throws PGPException {
        pww.appendLine("Signature Packet").iind()
                .appendLine("Version: " + signature.getVersion())
                .appendLine("Type: " + SignatureType.valueOf(signature.getSignatureType()))
                .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(signature.getKeyAlgorithm()))
                .appendLine("Hash Algorithm: " + HashAlgorithm.fromId(signature.getHashAlgorithm()));

        if (signature.getHashedSubPackets().toArray().length != 0) {
            pww.appendLine("Hashed Area:").iind();
            appendSubpacketVector(pww, signature.getHashedSubPackets());
            pww.dind();
        }

        if (signature.getUnhashedSubPackets().toArray().length != 0) {
            pww.appendLine("Unhashed Area:").iind();
            appendSubpacketVector(pww, signature.getUnhashedSubPackets());
            pww.dind();
        }

        pww.appendLine("Digest Prefix: " + Hex.toHexString(signature.getDigestPrefix()))
                .appendLine("Signature: ").iind()
                .appendLine(Hex.toHexString(signature.getSignature())).dind()
                .dind();
    }

    private static void appendSubpacketVector(PrintWriterWrapper pww, PGPSignatureSubpacketVector vector) throws PGPException {
        PGPSignatureList embeddedSignatures = vector.getEmbeddedSignatures();
        int embeddedSigCount = 0;

        for (SignatureSubpacket subpacket : vector.toArray()) {
            switch (org.pgpainless.algorithm.SignatureSubpacket.fromCode(subpacket.getType())) {
                case signatureCreationTime:
                    SignatureCreationTime signatureCreationTime = (SignatureCreationTime) subpacket;
                    pww.appendLine("Signature Creation Time: " + DateUtil.formatUTCDate(signatureCreationTime.getTime()) + (signatureCreationTime.isCritical() ? " (critical)" : ""));
                    break;
                case signatureExpirationTime:
                    SignatureExpirationTime signatureExpirationTime = (SignatureExpirationTime) subpacket;
                    pww.appendLine("Signature Expiration Time: " + signatureExpirationTime.getTime() + (signatureExpirationTime.isCritical() ? " (critical)" : ""));
                    break;
                case exportableCertification:
                    Exportable exportable = (Exportable) subpacket;
                    pww.appendLine("Exportable: " + exportable.isExportable() + (exportable.isCritical() ? " (critical)" : ""));
                    break;
                case trustSignature:
                    TrustSignature trustSignature = (TrustSignature) subpacket;
                    pww.appendLine("Trust Signature" + (trustSignature.isCritical() ? " (critical)" : "") + ":").iind()
                            .appendLine("Depth: " + trustSignature.getDepth())
                            .appendLine("Amount: " + trustSignature.getTrustAmount())
                            .dind();
                    break;
                case regularExpression:
                    pww.appendLine("Regular Expression: " + new String(subpacket.getData()));
                    break;
                case revocable:
                    Revocable revocable = (Revocable) subpacket;
                    pww.appendLine("Revocable: " + revocable.isRevocable() + (revocable.isCritical() ? " (critical)" : ""));
                    break;
                case keyExpirationTime:
                    KeyExpirationTime keyExpirationTime = (KeyExpirationTime) subpacket;
                    pww.appendLine("Key Expiration Time: " + keyExpirationTime.getTime() + (keyExpirationTime.isCritical() ? " (critical)" : ""));
                    break;
                case placeholder:
                    pww.appendLine("Placeholder: " + new String(subpacket.getData()));
                    break;
                case preferredSymmetricAlgorithms:
                    PreferredAlgorithms preferredSymmetricAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] symAlgIds = preferredSymmetricAlgorithms.getPreferences();
                    SymmetricKeyAlgorithm[] symAlgs = new SymmetricKeyAlgorithm[symAlgIds.length];
                    for (int i = 0; i < symAlgs.length; i++) {
                        symAlgs[i] = SymmetricKeyAlgorithm.fromId(symAlgIds[i]);
                    }
                    pww.appendLine("Preferred Symmetric Algorithms: " + Arrays.toString(symAlgs) + (preferredSymmetricAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case revocationKey:
                    RevocationKey revocationKey = (RevocationKey) subpacket;
                    pww.appendLine("Revocation Key" + (revocationKey.isCritical() ? " (critical)" : "") + ":").iind()
                            .appendLine("Key Algorithm: " + PublicKeyAlgorithm.fromId(revocationKey.getAlgorithm()))
                            .appendLine("Signature Class: " + revocationKey.getSignatureClass())
                            .appendLine("Fingerprint: " + new String(revocationKey.getFingerprint()))
                            .dind();
                    break;
                case issuerKeyId:
                    IssuerKeyID issuerKeyID = (IssuerKeyID) subpacket;
                    pww.appendLine("Issuer Key ID: " + Long.toHexString(issuerKeyID.getKeyID()) + (issuerKeyID.isCritical() ? " (critical)" : ""));
                    break;
                case notationData:
                    NotationData notationData = (NotationData) subpacket;
                    pww.appendLine("Notation Data" + (notationData.isCritical() ? " (critical)" : "") + ":").iind()
                            .appendLine("Notation Name: " + notationData.getNotationName())
                            .appendLine("Notation Value: " + notationData.getNotationValue())
                            .dind();
                    break;
                case preferredHashAlgorithms:
                    PreferredAlgorithms preferredHashAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] hashAlgIds = preferredHashAlgorithms.getPreferences();
                    HashAlgorithm[] hashAlgs = new HashAlgorithm[hashAlgIds.length];
                    for (int i = 0; i < hashAlgs.length; i++) {
                        hashAlgs[i] = HashAlgorithm.fromId(hashAlgIds[i]);
                    }
                    pww.appendLine("Preferred Hash Algorithms: " + Arrays.toString(hashAlgs) + (preferredHashAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case preferredCompressionAlgorithms:
                    PreferredAlgorithms preferredCompressionAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] compAlgIds = preferredCompressionAlgorithms.getPreferences();
                    CompressionAlgorithm[] compAlgs = new CompressionAlgorithm[compAlgIds.length];
                    for (int i = 0; i < compAlgs.length; i++) {
                        compAlgs[i] = CompressionAlgorithm.fromId(compAlgIds[i]);
                    }
                    pww.appendLine("Preferred Compression Algorithms: " + Arrays.toString(compAlgs) + (preferredCompressionAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case keyServerPreferences:
                    KeyServerPreferences preferences = new KeyServerPreferences(subpacket);
                    pww.appendLine("Key Server Preferences: " + Arrays.toString(preferences.getPreferences().toArray(new KeyServerPreferences.Pref[0])));
                    break;
                case preferredKeyServers:
                    pww.appendLine("Preferred Key Servers: " + new String(subpacket.getData()));
                    break;
                case primaryUserId:
                    PrimaryUserID primaryUserID = (PrimaryUserID) subpacket;
                    pww.appendLine("Primary User-ID: " + primaryUserID.isPrimaryUserID() + (primaryUserID.isCritical() ? " (critical)" : ""));
                    break;
                case policyUrl:
                    pww.appendLine("Policy-URL: " + new String(subpacket.getData()));
                    break;
                case keyFlags:
                    KeyFlags keyFlags = (KeyFlags) subpacket;
                    KeyFlag[] flags = KeyFlag.fromBitmask(keyFlags.getFlags()).toArray(new KeyFlag[0]);
                    pww.appendLine("Key Flags: " + Arrays.toString(flags) + (keyFlags.isCritical() ? " (critical)" : ""));
                    break;
                case signerUserId:
                    SignerUserID signerUserID = (SignerUserID) subpacket;
                    pww.appendLine("Signer User-ID: " + signerUserID.getID() + (signerUserID.isCritical() ? " (critical)" : ""));
                    break;
                case revocationReason:
                    RevocationReason revocationReason = (RevocationReason) subpacket;
                    pww.appendLine("Revocation Reason: " + RevocationAttributes.Reason.fromCode(revocationReason.getRevocationReason()) + (revocationReason.isCritical() ? " (critical)" : "")).iind()
                            .appendLine("Description: " + revocationReason.getRevocationDescription()).dind();
                    break;
                case features:
                    Features features = (Features) subpacket;
                    Feature[] featurez = Feature.fromBitmask(features.getFeatures()).toArray(new Feature[0]);
                    pww.appendLine("Features: " + Arrays.toString(featurez) + (features.isCritical() ? " (critical)" : ""));
                    break;
                case signatureTarget:
                    SignatureTarget signatureTarget = (SignatureTarget) subpacket;
                    pww.appendLine("Signature Target" + (signatureTarget.isCritical() ? " (critical)" : "" + ":")).iind()
                            .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(signatureTarget.getPublicKeyAlgorithm()))
                            .appendLine("Hash Algorithm: " + HashAlgorithm.fromId(signatureTarget.getHashAlgorithm()))
                            .appendLine("Hash Data: " + Hex.toHexString(signatureTarget.getHashData()))
                            .dind();
                    break;
                case embeddedSignature:
                    EmbeddedSignature embeddedSignature = (EmbeddedSignature) subpacket;
                    pww.appendLine("Embedded Signature" + (embeddedSignature.isCritical() ? " (critical)" : "") + ":").iind();
                    appendSignature(pww, embeddedSignatures.get(embeddedSigCount++));
                    break;
                case issuerFingerprint:
                    IssuerFingerprint issuerFingerprint = (IssuerFingerprint) subpacket;
                    pww.appendLine("Issuer Fingerprint: " + Hex.toHexString(issuerFingerprint.getFingerprint()) + (issuerFingerprint.isCritical() ? " (critical)" : ""));
                    break;
                case preferredAEADAlgorithms:
                    PreferredAlgorithms preferredAEADAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] aeadAlgIds = preferredAEADAlgorithms.getPreferences();
                    pww.appendLine("Preferred AEAD Algorithms: " + Arrays.toString(aeadAlgIds) + (preferredAEADAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case intendedRecipientFingerprint:
                    IntendedRecipientFingerprint intendedRecipientFingerprint = (IntendedRecipientFingerprint) subpacket;
                    pww.appendLine("Intended Recipient Fingerprint" + (intendedRecipientFingerprint.isCritical() ? " critical" : "") + ":").iind()
                            .appendLine("Key Version: " + intendedRecipientFingerprint.getKeyVersion())
                            .appendLine("Fingerprint: " + Hex.toHexString(intendedRecipientFingerprint.getFingerprint()))
                            .dind();
                    break;
                case attestedCertification:
                    pww.appendLine("Attested Certification: " + new String(subpacket.getData()));
                    break;
                default:
                    int type = subpacket.getType();
                    if (type >= 60 && type <= 63) {
                        pww.appendLine("Experimental Subpacket (Tag " + type + ")" + (subpacket.isCritical() ? " (critical)" : "") + ":" + new String(subpacket.getData()));
                    } else {
                        pww.appendLine("Unknown Subpacket (Tag " + type + ")" + (subpacket.isCritical() ? " (critical)" : "") + ":" + new String(subpacket.getData()));
                    }
            }
        }
    }

    public static class PrintWriterWrapper {
        private final int spacesPerLevel = 2;

        private final PrintWriter pw;
        private int indentationLevel = 0;

        public PrintWriterWrapper(PrintWriter pw) {
            this.pw = pw;
        }

        public PrintWriterWrapper appendLine(String line) {
            spaces();
            pw.write(line);
            pw.write('\n');
            return this;
        }

        public PrintWriterWrapper iind() {
            indentationLevel++;
            return this;
        }

        public PrintWriterWrapper dind() {
            indentationLevel--;
            return this;
        }

        public PrintWriterWrapper emptyLine() {
            pw.write('\n');
            return this;
        }

        private PrintWriterWrapper spaces() {
            for (int i = 0; i < indentationLevel * spacesPerLevel; i++) {
                pw.write(' ');
            }
            return this;
        }
    }
}
