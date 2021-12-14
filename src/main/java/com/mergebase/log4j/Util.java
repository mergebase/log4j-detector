package com.mergebase.log4j;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.LinkedList;
import java.util.jar.JarFile;
import java.util.zip.ZipFile;

public class Util {

    private static final int REGULAR_CLOSE = 0;
    private static final int CLOSE_AND_COMMIT = 1;

    public static void close(Object o1, Object o2, Object o3) {
        close(o1, o2, o3, null, null);
    }

    public static void close(Object o1, Object o2, Object o3, Object o4, Object o5) {
        close(REGULAR_CLOSE, o1, o2, o3, o4, o5);
    }

    private static void close(int flag, Object... closeArgs) {
        if (closeArgs == null || closeArgs.length == 0) {
            return;
        }

        LinkedList<Throwable> closingProblems = new LinkedList<>();
        for (Object o : closeArgs) {
            if (o == null) {
                continue;
            }
            try {
                if (o instanceof ResultSet) {
                    ((ResultSet) o).close();
                } else if (o instanceof Statement) {
                    ((Statement) o).close();
                } else if (o instanceof Connection) {
                    ((Connection) o).close();
                } else if (o instanceof Reader) {
                    ((Reader) o).close();
                } else if (o instanceof Writer) {
                    ((Writer) o).close();
                } else if (o instanceof InputStream) {
                    ((InputStream) o).close();
                } else if (o instanceof OutputStream) {
                    ((OutputStream) o).close();
                } else if (o instanceof JarFile) {
                    ((JarFile) o).close();
                } else if (o instanceof ZipFile) {
                    ((ZipFile) o).close();
                } else if (o instanceof Process) {
                    ((Process) o).destroy();
                } else {
                    throw new IllegalArgumentException("cannot close: " + o.getClass());
                }
            } catch (Throwable t) {
                closingProblems.add(t);
            }
        }

        // Let the close & commit method above handle this instead.
        if (flag == CLOSE_AND_COMMIT && !closingProblems.isEmpty()) {
            throw new CloseFailedException(closingProblems);
        }

        if (!closingProblems.isEmpty()) {
            Throwable t = closingProblems.get(0);
            Throwables.rethrowIfUnchecked(t);
            throw new RuntimeException("Failed to close something: " + t, t);
        }
    }

    private static class CloseFailedException extends RuntimeException {
        public final LinkedList<Throwable> closingProblems;

        public CloseFailedException(LinkedList<Throwable> closingProblems) {
            this.closingProblems = closingProblems;
        }
    }
}
