package com.mergebase.log4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

public class Bytes {

    public static final int SIZE_KEY = 0;
    public static final int LAST_READ_KEY = 1;

    public static final Charset UTF_8;

    static {
        try {
            UTF_8 = Charset.forName("UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("could not obtain UTF-8 charset...", e);
        }
    }

    public static byte[] fileToBytes(File f) {
        FileInputStream fin;
        try {
            fin = new FileInputStream(f);
            if (f.length() <= 32768) {
                try {
                    byte[] buf = new byte[(int) f.length()];
                    fill(buf, 0, fin);
                    return buf;
                } finally {
                    fin.close();
                }
            } else {
                return streamToBytes(fin);
            }
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to read file [" + f.getName() + "] " + ioe, ioe);
        }
    }

    public static byte[] fromString(String s) {
        return s.getBytes(UTF_8);
    }

    public static byte[] streamToBytes(final InputStream in) throws IOException {
        return streamToBytes(in, true, -1);
    }

    public static byte[] streamToBytes(final InputStream in, final boolean doClose) throws IOException {
        return streamToBytes(in, doClose, true, -1);
    }

    public static byte[] streamToBytes(final InputStream in, final boolean doClose, final long lengthHint) throws IOException {
        return streamToBytes(in, doClose, true, lengthHint);
    }

    public static byte[] streamToBytes(
            final InputStream in, final boolean doClose, final boolean doResize, long lengthHint
    ) throws IOException {
        byte[] buf;
        if (lengthHint > 0) {
            buf = new byte[(int) lengthHint];
        } else {
            buf = new byte[32768];
        }
        try {
            int[] status = fill(buf, 0, in);
            int size = status[SIZE_KEY];
            int lastRead = status[LAST_READ_KEY];
            if (doResize) {
                while (lastRead != -1) {
                    buf = resizeArray(buf);
                    status = fill(buf, size, in);
                    size = status[SIZE_KEY];
                    lastRead = status[LAST_READ_KEY];
                }
            }
            if (buf.length != size) {
                byte[] smallerBuf = new byte[size];
                System.arraycopy(buf, 0, smallerBuf, 0, size);
                buf = smallerBuf;
            }
        } finally {
            if (doClose) {
                in.close();
            }
        }
        return buf;
    }

    public static int[] fill(
            final byte[] buf, final int offset, final InputStream in
    ) throws IOException {
        int read = in.read(buf, offset, buf.length - offset);
        int lastRead = read;
        if (read == -1) {
            read = 0;
        }
        while (lastRead != -1 && read + offset < buf.length) {
            lastRead = in.read(buf, offset + read, buf.length - read - offset);
            if (lastRead != -1) {
                read += lastRead;
            }
        }
        // If read + offset == buf.length, we are done!
        return new int[]{offset + read, read + offset == buf.length ? -1 : lastRead};
    }

    public static byte[] resizeArray(final byte[] bytes) {
        byte[] biggerBytes = new byte[bytes.length * 2];
        System.arraycopy(bytes, 0, biggerBytes, 0, bytes.length);
        return biggerBytes;
    }

    /**
     * Knuth-Morris-Pratt
     *
     * @param data    search data
     * @param pattern pattern to look for
     * @return index of match or -1 if no match
     */
    public static int kmp(byte[] data, byte[] pattern) {
        if (data.length == 0) {
            return -1;
        }

        int[] failure = kmpFailure(pattern);
        int j = 0;

        for (int i = 0; i < data.length; i++) {
            while (j > 0 && pattern[j] != data[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == data[i]) {
                j++;
            }
            if (j == pattern.length) {
                return i - pattern.length + 1;
            }
        }
        return -1;
    }

    private static int[] kmpFailure(byte[] pattern) {
        int[] failure = new int[pattern.length];

        int j = 0;
        for (int i = 1; i < pattern.length; i++) {
            while (j > 0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }

}
