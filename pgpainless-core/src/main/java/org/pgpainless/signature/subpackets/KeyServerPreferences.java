package org.pgpainless.signature.subpackets;

import java.sql.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

public class KeyServerPreferences {

    public enum Pref {
        NO_MODIFY (0x80),
        ;

        static final Map<Integer, Pref> MAP = new HashMap<>();

        static {
            for (Pref pref : values()) {
                MAP.put(pref.code, pref);
            }
        }

        public static Pref fromCode(int code) {
            return MAP.get(code);
        }

        private int code;

        public int getCode() {
            return code;
        }

        Pref(int code) {
            this.code = code;
        }
    }

    private List<Pref> prefList = new ArrayList<>();

    public KeyServerPreferences(SignatureSubpacket subpacket) {
        if (subpacket.getType() != SignatureSubpacketTags.KEY_SERVER_PREFS) {
            throw new IllegalArgumentException("Wrong Packet Tag.");
        }

        for (byte octet : subpacket.getData()) {
            this.prefList.add(Pref.fromCode(octet & 0xff));
        }
    }

    public List<Pref> getPreferences() {
        return new ArrayList<>(prefList);
    }
}
