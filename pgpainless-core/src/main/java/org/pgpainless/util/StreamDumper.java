package org.pgpainless.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

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
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
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

public class StreamDumper {

    public static void dump(InputStream inputStream, PGPSessionKey sessionKey) throws IOException, PGPException {

        StringBuilder stringBuilder = new StringBuilder();
        StringBuilderWrapper sbw = new StringBuilderWrapper(stringBuilder);

        PGPObjectFactory objectFactory = new BcPGPObjectFactory(inputStream);
        walkObjects(sbw, objectFactory, sessionKey);

        System.out.println(sbw);
    }

    private static void walkObjects(StringBuilderWrapper sbw, PGPObjectFactory objectFactory, PGPSessionKey sessionKey) throws IOException, PGPException {
        Object next;

        while ((next = objectFactory.nextObject()) != null) {

            if (next instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) next;
                Iterator<PGPOnePassSignature> iterator = onePassSignatures.iterator();
                while (iterator.hasNext()) {
                    PGPOnePassSignature pgpOnePassSignature = iterator.next();
                    sbw.appendLine("One-Pass Signature Packet").iind()
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
                    appendSignature(sbw, signature);
                    sbw.emptyLine();
                }
            }
            else if (next instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) next;
                SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory = null;
                if (sessionKey != null) {
                    sessionKeyDataDecryptorFactory = new BcSessionKeyDataDecryptorFactory(sessionKey);
                }
                for (PGPEncryptedData encryptedData : encryptedDataList) {
                    if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                        PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) encryptedData;
                        sbw.appendLine("Public-Key Encrypted Session Key Packet").iind()
                                .appendLine("Recipient: " + Long.toHexString(pkesk.getKeyID()));

                        if (sessionKeyDataDecryptorFactory != null) {
                            try {
                                InputStream inputStream = pkesk.getDataStream(sessionKeyDataDecryptorFactory);
                                sbw.appendLine("Session Key: " + Hex.toHexString(sessionKey.getKey()));
                                sbw.appendLine("Symmetric Algorithm: " + SymmetricKeyAlgorithm.fromId(sessionKey.getAlgorithm()));
                                sbw.appendLine("Decryption Successful");
                                sbw.emptyLine();

                                PGPObjectFactory decryptedFactory = new BcPGPObjectFactory(inputStream);
                                walkObjects(sbw, decryptedFactory, sessionKey);
                            } catch (PGPException e) {
                                sbw.appendLine("Decryption Failed");
                            }
                        }

                        if (pkesk.isIntegrityProtected()) {
                            sbw.appendLine("Modification Detection Code Packet").iind()
                                    .appendLine("Valid: " + pkesk.verify())
                                    .dind();
                        }
                    } else if (encryptedData instanceof PGPPBEEncryptedData) {
                        PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) encryptedData;
                        sbw.appendLine("Symmetric-Key Encrypted Session Key Packet").iind()
                                .appendLine("Integrity Protected: " + skesk.isIntegrityProtected())
                                .dind().emptyLine();
                    }
                }
                sbw.emptyLine();
            }
            else if (next instanceof PGPLiteralData) {
                PGPLiteralData literalData = (PGPLiteralData) next;
                StreamEncoding encoding = StreamEncoding.fromCode(literalData.getFormat());
                String fileName = literalData.getFileName();
                Date modificationDate = literalData.getModificationTime();

                sbw.appendLine("Literal Data Packet").iind()
                        .appendLine("Format: " + encoding);
                if (fileName != null && !fileName.isEmpty()) {
                    sbw.appendLine("File Name: " + fileName);
                }
                if (modificationDate != null && modificationDate.getTime() != 0) {
                    sbw.appendLine("Modification Date: " + DateUtil.formatUTCDate(modificationDate));
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
                sbw.appendLine("Content: \"" + content + "\"")
                        .dind()
                        .emptyLine();
            }
            else if (next instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) next;
                sbw.appendLine("Compressed Data Packet").iind()
                        .appendLine("Algorithm: " + CompressionAlgorithm.fromId(compressedData.getAlgorithm()))
                        .emptyLine();

                PGPObjectFactory compressedFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                walkObjects(sbw, compressedFactory, sessionKey);
                sbw.dind();
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

    private static void appendSignature(StringBuilderWrapper sbw, PGPSignature signature) throws PGPException {
        sbw.appendLine("Signature Packet").iind()
                .appendLine("Version: " + signature.getVersion())
                .appendLine("Type: " + SignatureType.valueOf(signature.getSignatureType()))
                .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(signature.getKeyAlgorithm()))
                .appendLine("Hash Algorithm: " + HashAlgorithm.fromId(signature.getHashAlgorithm()));

        if (signature.getHashedSubPackets().toArray().length != 0) {
            sbw.appendLine("Hashed Area:").iind();
            appendSubpacketVector(sbw, signature.getHashedSubPackets());
            sbw.dind();
        }

        if (signature.getUnhashedSubPackets().toArray().length != 0) {
            sbw.appendLine("Unhashed Area:").iind();
            appendSubpacketVector(sbw, signature.getUnhashedSubPackets());
            sbw.dind();
        }

        sbw.appendLine("Digest Prefix: " + Hex.toHexString(signature.getDigestPrefix()))
                .appendLine("Signature: ").iind()
                .appendLine(Hex.toHexString(signature.getSignature())).dind()
                .dind();
    }

    private static void appendSubpacketVector(StringBuilderWrapper sbw, PGPSignatureSubpacketVector vector) throws PGPException {
        PGPSignatureList embeddedSignatures = vector.getEmbeddedSignatures();
        int embeddedSigCount = 0;

        for (SignatureSubpacket subpacket : vector.toArray()) {
            switch (org.pgpainless.algorithm.SignatureSubpacket.fromCode(subpacket.getType())) {
                case signatureCreationTime:
                    SignatureCreationTime signatureCreationTime = (SignatureCreationTime) subpacket;
                    sbw.appendLine("Signature Creation Time: " + DateUtil.formatUTCDate(signatureCreationTime.getTime()) + (signatureCreationTime.isCritical() ? " (critical)" : ""));
                    break;
                case signatureExpirationTime:
                    SignatureExpirationTime signatureExpirationTime = (SignatureExpirationTime) subpacket;
                    sbw.appendLine("Signature Expiration Time: " + signatureExpirationTime.getTime() + (signatureExpirationTime.isCritical() ? " (critical)" : ""));
                    break;
                case exportableCertification:
                    Exportable exportable = (Exportable) subpacket;
                    sbw.appendLine("Exportable: " + exportable.isExportable() + (exportable.isCritical() ? " (critical)" : ""));
                    break;
                case trustSignature:
                    TrustSignature trustSignature = (TrustSignature) subpacket;
                    sbw.appendLine("Trust Signature" + (trustSignature.isCritical() ? " (critical)" : "") + ":").iind()
                            .appendLine("Depth: " + trustSignature.getDepth())
                            .appendLine("Amount: " + trustSignature.getTrustAmount())
                            .dind();
                    break;
                case regularExpression:
                    sbw.appendLine("Regular Expression: " + new String(subpacket.getData()));
                    break;
                case revocable:
                    Revocable revocable = (Revocable) subpacket;
                    sbw.appendLine("Revocable: " + revocable.isRevocable() + (revocable.isCritical() ? " (critical)" : ""));
                    break;
                case keyExpirationTime:
                    KeyExpirationTime keyExpirationTime = (KeyExpirationTime) subpacket;
                    sbw.appendLine("Key Expiration Time: " + keyExpirationTime.getTime() + (keyExpirationTime.isCritical() ? " (critical)" : ""));
                    break;
                case placeholder:
                    sbw.appendLine("Placeholder: " + new String(subpacket.getData()));
                    break;
                case preferredSymmetricAlgorithms:
                    PreferredAlgorithms preferredSymmetricAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] symAlgIds = preferredSymmetricAlgorithms.getPreferences();
                    SymmetricKeyAlgorithm[] symAlgs = new SymmetricKeyAlgorithm[symAlgIds.length];
                    for (int i = 0; i < symAlgs.length; i++) {
                        symAlgs[i] = SymmetricKeyAlgorithm.fromId(symAlgIds[i]);
                    }
                    sbw.appendLine("Preferred Symmetric Algorithms: " + Arrays.toString(symAlgs) + (preferredSymmetricAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case revocationKey:
                    RevocationKey revocationKey = (RevocationKey) subpacket;
                    sbw.appendLine("Revocation Key" + (revocationKey.isCritical() ? " (critical)" : "") + ":").iind()
                            .appendLine("Key Algorithm: " + PublicKeyAlgorithm.fromId(revocationKey.getAlgorithm()))
                            .appendLine("Signature Class: " + revocationKey.getSignatureClass())
                            .appendLine("Fingerprint: " + new String(revocationKey.getFingerprint()))
                            .dind();
                    break;
                case issuerKeyId:
                    IssuerKeyID issuerKeyID = (IssuerKeyID) subpacket;
                    sbw.appendLine("Issuer Key ID: " + Long.toHexString(issuerKeyID.getKeyID()) + (issuerKeyID.isCritical() ? " (critical)" : ""));
                    break;
                case notationData:
                    NotationData notationData = (NotationData) subpacket;
                    sbw.appendLine("Notation Data" + (notationData.isCritical() ? " (critical)" : "") + ":").iind()
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
                    sbw.appendLine("Preferred Hash Algorithms: " + Arrays.toString(hashAlgs) + (preferredHashAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case preferredCompressionAlgorithms:
                    PreferredAlgorithms preferredCompressionAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] compAlgIds = preferredCompressionAlgorithms.getPreferences();
                    CompressionAlgorithm[] compAlgs = new CompressionAlgorithm[compAlgIds.length];
                    for (int i = 0; i < compAlgs.length; i++) {
                        compAlgs[i] = CompressionAlgorithm.fromId(compAlgIds[i]);
                    }
                    sbw.appendLine("Preferred Compression Algorithms: " + Arrays.toString(compAlgs) + (preferredCompressionAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case keyServerPreferences:
                    sbw.appendLine("Key Server Preferences: " + new String(subpacket.getData()));
                    break;
                case preferredKeyServers:
                    sbw.appendLine("Preferred Key Servers: " + new String(subpacket.getData()));
                    break;
                case primaryUserId:
                    PrimaryUserID primaryUserID = (PrimaryUserID) subpacket;
                    sbw.appendLine("Primary User-ID: " + primaryUserID.isPrimaryUserID() + (primaryUserID.isCritical() ? " (critical)" : ""));
                    break;
                case policyUrl:
                    sbw.appendLine("Policy-URL: " + new String(subpacket.getData()));
                    break;
                case keyFlags:
                    KeyFlags keyFlags = (KeyFlags) subpacket;
                    KeyFlag[] flags = KeyFlag.fromBitmask(keyFlags.getFlags()).toArray(new KeyFlag[0]);
                    sbw.appendLine("Key Flags: " + Arrays.toString(flags) + (keyFlags.isCritical() ? " (critical)" : ""));
                    break;
                case signerUserId:
                    SignerUserID signerUserID = (SignerUserID) subpacket;
                    sbw.appendLine("Signer User-ID: " + signerUserID.getID() + (signerUserID.isCritical() ? " (critical)" : ""));
                    break;
                case revocationReason:
                    RevocationReason revocationReason = (RevocationReason) subpacket;
                    sbw.appendLine("Revocation Reason: " + RevocationAttributes.Reason.fromCode(revocationReason.getRevocationReason()) + (revocationReason.isCritical() ? " (critical)" : "")).iind()
                            .appendLine("Description: " + revocationReason.getRevocationDescription()).dind();
                    break;
                case features:
                    Features features = (Features) subpacket;
                    Feature[] featurez = Feature.fromBitmask(features.getFeatures()).toArray(new Feature[0]);
                    sbw.appendLine("Features: " + Arrays.toString(featurez) + (features.isCritical() ? " (critical)" : ""));
                    break;
                case signatureTarget:
                    SignatureTarget signatureTarget = (SignatureTarget) subpacket;
                    sbw.appendLine("Signature Target" + (signatureTarget.isCritical() ? " (critical)" : "" + ":")).iind()
                            .appendLine("Public Key Algorithm: " + PublicKeyAlgorithm.fromId(signatureTarget.getPublicKeyAlgorithm()))
                            .appendLine("Hash Algorithm: " + HashAlgorithm.fromId(signatureTarget.getHashAlgorithm()))
                            .appendLine("Hash Data: " + Hex.toHexString(signatureTarget.getHashData()))
                            .dind();
                    break;
                case embeddedSignature:
                    EmbeddedSignature embeddedSignature = (EmbeddedSignature) subpacket;
                    sbw.appendLine("Embedded Signature" + (embeddedSignature.isCritical() ? " (critical)" : "") + ":").iind();
                    appendSignature(sbw, embeddedSignatures.get(embeddedSigCount++));
                    break;
                case issuerFingerprint:
                    IssuerFingerprint issuerFingerprint = (IssuerFingerprint) subpacket;
                    sbw.appendLine("Issuer Fingerprint: " + Hex.toHexString(issuerFingerprint.getFingerprint()) + (issuerFingerprint.isCritical() ? " (critical)" : ""));
                    break;
                case preferredAEADAlgorithms:
                    PreferredAlgorithms preferredAEADAlgorithms = (PreferredAlgorithms) subpacket;
                    int[] aeadAlgIds = preferredAEADAlgorithms.getPreferences();
                    sbw.appendLine("Preferred AEAD Algorithms: " + Arrays.toString(aeadAlgIds) + (preferredAEADAlgorithms.isCritical() ? " (critical)" : ""));
                    break;
                case intendedRecipientFingerprint:
                    IntendedRecipientFingerprint intendedRecipientFingerprint = (IntendedRecipientFingerprint) subpacket;
                    sbw.appendLine("Intended Recipient Fingerprint" + (intendedRecipientFingerprint.isCritical() ? " critical" : "") + ":").iind()
                            .appendLine("Key Version: " + intendedRecipientFingerprint.getKeyVersion())
                            .appendLine("Fingerprint: " + Hex.toHexString(intendedRecipientFingerprint.getFingerprint()))
                            .dind();
                    break;
                case attestedCertification:
                    sbw.appendLine("Attested Certification: " + new String(subpacket.getData()));
                    break;
                default:
                    sbw.appendLine("Experimental Subpacket (Tag " + subpacket.getType() + ")" + (subpacket.isCritical() ? " (critical)" : "") + ":" + new String(subpacket.getData()));
            }
        }
    }

    public static class StringBuilderWrapper {
        private final StringBuilder sb;
        private int indentationLevel = 0;
        private final int spacesPerLevel = 2;

        public StringBuilderWrapper(StringBuilder sb) {
            this.sb = sb;
        }

        public StringBuilderWrapper appendLine(String line) {
            spaces();
            sb.append(line).append('\n');
            return this;
        }

        public StringBuilderWrapper iind() {
            indentationLevel++;
            return this;
        }

        public StringBuilderWrapper dind() {
            indentationLevel--;
            return this;
        }

        public StringBuilderWrapper emptyLine() {
            sb.append('\n');
            return this;
        }

        private StringBuilderWrapper spaces() {
            for (int i = 0; i < indentationLevel * spacesPerLevel; i++) {
                sb.append(' ');
            }
            return this;
        }

        public String toString() {
            return sb.toString();
        }
    }
}