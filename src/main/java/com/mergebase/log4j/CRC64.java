package com.mergebase.log4j;

public class CRC64 {
    private static final long P = 0x42F0E1EBA9EA3693L;
    private static final long[] T = new long[256];
    private static final byte[] NULL_BYTES_REPLACEMENT = "\u0000".getBytes(Bytes.UTF_8);

    static {
        for (int b = 0; b < T.length; ++b) {
            long r = b;
            for (int i = 0; i < 8; ++i) {
                if ((r & 1) == 1) {
                    r = (r >>> 1) ^ P;
                } else {
                    r >>>= 1;
                }
            }
            T[b] = r;
        }
    }

    static long hash(byte[] bytes) {
        long crc = -1;
        if (bytes == null) {
            bytes = NULL_BYTES_REPLACEMENT;
        }
        for (byte b : bytes) {
            crc = T[(b ^ (int) crc) & 0xFF] ^ (crc >>> 8);
        }
        return Math.abs(~crc);
    }

    static long hash(String s) {
        byte[] bytes = s != null ? s.getBytes(Bytes.UTF_8) : null;
        return hash(bytes);
    }

}
