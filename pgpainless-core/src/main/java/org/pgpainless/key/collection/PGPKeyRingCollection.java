package org.pgpainless.key.collection;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * This class describes a logic of handling a collection of different {@link PGPKeyRing}. The logic was inspired by
 * {@link PGPSecretKeyRingCollection} and {@link PGPPublicKeyRingCollection}.
 */
public class PGPKeyRingCollection {
    private PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
    private PGPPublicKeyRingCollection pgpPublicKeyRingCollection;

    public PGPKeyRingCollection(@Nonnull byte[] encoding, @Nonnull KeyFingerPrintCalculator fingerPrintCalculator,
                                boolean isSilent) throws IOException, PGPException {
        this(new ByteArrayInputStream(encoding), fingerPrintCalculator, isSilent);
    }

    /**
     * Build a {@link PGPKeyRingCollection} from the passed in input stream.
     *
     * @param in       input stream containing data
     * @param isSilent flag indicating that unsupported objects will be ignored
     * @throws IOException  if a problem parsing the base stream occurs
     * @throws PGPException if an object is encountered which isn't a {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}
     */
    public PGPKeyRingCollection(@Nonnull InputStream in, @Nonnull KeyFingerPrintCalculator fingerPrintCalculator,
                                boolean isSilent) throws IOException, PGPException {
        PGPObjectFactory pgpFact = new PGPObjectFactory(in, fingerPrintCalculator);
        Object obj;

        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        List<PGPPublicKeyRing> publicKeyRings = new ArrayList<>();

        while ((obj = pgpFact.nextObject()) != null) {
            if (obj instanceof PGPSecretKeyRing) {
                secretKeyRings.add((PGPSecretKeyRing) obj);
            } else if (obj instanceof PGPPublicKeyRing) {
                publicKeyRings.add((PGPPublicKeyRing) obj);
            } else if (!isSilent) {
                throw new PGPException(obj.getClass().getName() + " found where " +
                        PGPSecretKeyRing.class.getSimpleName() + " or " +
                        PGPPublicKeyRing.class.getSimpleName() + " expected");
            }
        }

        pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(secretKeyRings);
        pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicKeyRings);
    }

    public PGPKeyRingCollection(Collection<PGPKeyRing> collection, boolean isSilent) throws IOException, PGPException {
        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        List<PGPPublicKeyRing> publicKeyRings = new ArrayList<>();

        for (PGPKeyRing pgpKeyRing : collection) {
            if (pgpKeyRing instanceof PGPSecretKeyRing) {
                secretKeyRings.add((PGPSecretKeyRing) pgpKeyRing);
            } else if (pgpKeyRing instanceof PGPPublicKeyRing) {
                publicKeyRings.add((PGPPublicKeyRing) pgpKeyRing);
            } else if (!isSilent) {
                throw new PGPException(pgpKeyRing.getClass().getName() + " found where " +
                        PGPSecretKeyRing.class.getSimpleName() + " or " +
                        PGPPublicKeyRing.class.getSimpleName() + " expected");
            }
        }

        pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(secretKeyRings);
        pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicKeyRings);
    }

    public PGPSecretKeyRingCollection getPGPSecretKeyRingCollection() {
        return pgpSecretKeyRingCollection;
    }

    public PGPPublicKeyRingCollection getPgpPublicKeyRingCollection() {
        return pgpPublicKeyRingCollection;
    }

    /**
     * Return the number of rings in this collection.
     *
     * @return total size of {@link PGPSecretKeyRingCollection} and {@link PGPPublicKeyRingCollection}
     * in this collection
     */
    public int size() {
        return pgpSecretKeyRingCollection.size() + pgpPublicKeyRingCollection.size();
    }
}
