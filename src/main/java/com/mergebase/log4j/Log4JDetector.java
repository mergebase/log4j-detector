package com.mergebase.log4j;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Log4JDetector {

    private static final String FILE_LOG4J_1 = "core/LogEvent.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2 = "core/Appender.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_3 = "core/Filter.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_4 = "core/Layout.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_5 = "core/LoggerContext.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2_10 = "appender/nosql/NoSqlAppender.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_VULNERABLE = "JndiLookup.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_SAFE_CONDITION1 = "JndiManager.class".toLowerCase(Locale.ROOT);

    // This occurs in "JndiManager.class" in 2.15.0
    private static byte[] IS_LOG4J_SAFE_2_15_0 = Bytes.fromString("Invalid JNDI URI - {}");

    // This occurs in "JndiManager.class" in 2.16.0
    private static byte[] IS_LOG4J_SAFE_2_16_0 = Bytes.fromString("log4j2.enableJndi");

    // This occurs in "JndiLookup.class" before 2.12.2
    private static byte[] IS_LOG4J_NOT_SAFE_2_12_2 = Bytes.fromString("Error looking up JNDI resource [{}].");

    private static boolean verbose = false;
    private static boolean debug = false;
    private static boolean foundHits = false;

    public static void main(String[] args) throws Exception {
        List<String> argsList = new ArrayList<>(Arrays.asList(args));
        Iterator<String> it = argsList.iterator();
        while (it.hasNext()) {
            final String argOrig = it.next();
            if ("--debug".equals(argOrig)) {
                debug = true;
                it.remove();
            } else if ("--verbose".equals(argOrig)) {
                verbose = true;
                it.remove();
            } else {
                File f = new File(argOrig);
                if (!f.exists()) {
                    System.out.println("Invalid file: [" + f.getPath() + "]");
                    System.exit(102);
                }
            }
        }

        if (argsList.isEmpty()) {
            System.out.println();
            System.out.println("Usage: java -jar log4j-detector-2021.12.14.jar [--verbose] [paths to scan...]");
            System.out.println();
            System.out.println("Exit codes:  0 = No vulnerable Log4J versions found.");
            System.out.println("             2 = At least one vulnerable Log4J version found.");
            System.out.println();
            System.out.println("About - MergeBase log4j detector (version 2021.12.14)");
            System.out.println("Docs  - https://github.com/mergebase/log4j-detector ");
            System.out.println("(C) Copyright 2021 Mergebase Software Inc. Licensed to you via GPLv3.");
            System.out.println();
            System.exit(100);
        }

        System.out.println("-- Analyzing paths (could take a long time).");
        System.out.println("-- Note: specify the '--verbose' flag to have every file examined printed to STDERR.");
        for (String arg : argsList) {
            File dir = new File(arg);
            analyze(dir);
        }
        if (foundHits) {
            System.exit(2);
        } else {
            System.out.println("-- No vulnerable Log4J 2.x samples found in supplied paths: " + argsList);
            System.out.println("-- Congratulations, the supplied paths are not vulnerable to CVE-2021-44228 !  :-) ");
        }
    }

    private static int[] pop4(InputStream in) throws IOException {
        int[] four = new int[4];
        four[0] = in.read();
        four[1] = in.read();
        four[2] = in.read();
        four[3] = in.read();
        return four;
    }

    private static int nextByte(int[] four, InputStream in) throws IOException {
        four[0] = four[1];
        four[1] = four[2];
        four[2] = four[3];
        four[3] = in.read();
        return four[3];
    }

    private static boolean isZipSentinel(int[] four) {
        return four[0] == 0x50 && four[1] == 0x4B && four[2] == 3 && four[3] == 4;
    }

    private final static Comparator<File> FILES_ORDER_BY_NAME = new Comparator<File>() {
        @Override
        public int compare(File f1, File f2) {
            String s1 = f1 != null ? f1.getName() : "";
            String s2 = f2 != null ? f2.getName() : "";
            int c = s1.compareToIgnoreCase(s2);
            if (c == 0) {
                c = s1.compareTo(s2);
                if (c == 0 && f1 != null) {
                    c = f1.compareTo(f2);
                }
            }
            return c;
        }
    };

    private final static Comparator<String> CASE_SENSITIVE_SANE = new Comparator<String>() {
        @Override
        public int compare(String s1, String s2) {
            int c = s1.compareToIgnoreCase(s2);
            if (c == 0) {
                c = s1.compareTo(s2);
            }
            return c;
        }
    };

    /**
     * @param fileName
     * @return 0 == zip, 1 == class, -1 = who knows...
     */
    private static int fileType(String fileName) {
        int c = fileName.lastIndexOf('.');
        if (c >= 0) {
            String suffix = fileName.substring(c + 1);
            if ("class".equalsIgnoreCase(suffix)) {
                return 1;
            } else if ("zip".equalsIgnoreCase(suffix)
                    || "jar".equalsIgnoreCase(suffix)
                    || "war".equalsIgnoreCase(suffix)
                    || "ear".equalsIgnoreCase(suffix)
                    || "aar".equalsIgnoreCase(suffix)) {
                return 0;
            }
        }
        return -1;
    }

    private static void findLog4jRecursive(
            final String zipPath, final Zipper zipper
    ) {
        ZipInputStream zin;
        try {
            zin = zipper.getFreshZipStream();
        } catch (Exception e) {
            System.out.println("-- Problem: " + zipPath + " - " + e);
            if (verbose) {
                System.err.println("-- Problem: " + zipPath + " - " + e);
                e.printStackTrace(System.err);
            }
            return;
        }
        if (zin == null) {
            if (fileType(zipPath) == 0) {
                System.out.println("-- Problem: " + zipPath + " - Not actually a zip!?! (no magic number)");
                if (verbose) {
                    System.err.println("-- Problem: " + zipPath + " - Not actually a zip!?! (no magic number)");
                }
            } else {
                if (verbose) {
                    System.err.println("-- Ignoring: " + zipPath + " - (not a zip)");
                }
            }
            return;
        } else {
            if (verbose) {
                System.err.println("-- Examining " + zipPath + "... ");
            }
        }

        boolean isZip = false;
        boolean conditionsChecked = false;
        boolean[] log4jProbe = new boolean[5];
        boolean isLog4j2_10 = false;
        boolean hasJndiLookup = false;
        boolean hasJndiManager = false;
        boolean isLog4j2_15 = false;
        boolean isLog4j2_15_override = false;
        boolean isLog4j2_12_2 = false;
        boolean isLog4j2_12_2_override = false;
        ZipEntry ze;
        while (true) {
            try {
                ze = zin.getNextEntry();
            } catch (Exception oops) {
                System.out.println("-- Problem " + zipPath + " - " + oops);
                if (verbose) {
                    System.err.println("-- Problem: " + zipPath + " - " + oops);
                    oops.printStackTrace(System.err);
                }
                break;
            }
            if (ze == null) {
                break;
            }
            isZip = true;
            conditionsChecked = true;
            if (ze.isDirectory()) {
                continue;
            }

            long zipEntrySize = ze.getSize();
            final String path = ze.getName().trim();
            String pathLower = path.toLowerCase(Locale.ROOT);
            final String fullPath = zipPath + "!/" + path;

            int fileType = fileType(path);
            boolean isSubZip = fileType == 0;
            boolean isClassEntry = fileType == 1;
            boolean needClassBytes = false;

            if (isClassEntry && pathLower.endsWith(FILE_LOG4J_VULNERABLE)) {
                needClassBytes = true;
            } else if (isClassEntry && pathLower.endsWith(FILE_LOG4J_SAFE_CONDITION1)) {
                needClassBytes = true;
            }

            if (debug) {
                System.err.println("-- DEBUG - " + fullPath + " size=" + zipEntrySize + " isZip=" + isSubZip + " isClass=" + isClassEntry);
            }
            byte[] b = new byte[0];
            if (isSubZip || needClassBytes) {
                try {
                    b = Bytes.streamToBytes(zin, false, zipEntrySize);
                } catch (Exception e) {
                    System.out.println("-- Problem - could not extract " + fullPath + " (size=" + zipEntrySize + ") - " + e);
                    if (verbose) {
                        System.err.println("-- Problem - could not extract " + fullPath + " (size=" + zipEntrySize + ") - " + e);
                        e.printStackTrace(System.err);
                    }
                    continue;
                }
            }
            final byte[] bytes = b;

            if (isSubZip) {
                try {
                    Zipper recursiveZipper = new Zipper() {
                        public ZipInputStream getFreshZipStream() {
                            ByteArrayInputStream bin = new ByteArrayInputStream(bytes);

                            int pos = getZipStart(bin);
                            if (pos < 0) {
                                throw new RuntimeException("Inner-zip - could not find ZIP magic number: " + fullPath);
                            }
                            bin = new ByteArrayInputStream(bytes);
                            // Advance to beginning of zip...
                            for (int i = 0; i < pos; i++) {
                                int c = bin.read();
                                if (c < 0) {
                                    throw new RuntimeException("Inner-zip closed early i=" + i + " - should be impossible");
                                }
                            }
                            return new ZipInputStream(bin);
                        }

                        public void close() {
                        }
                    };

                    findLog4jRecursive(fullPath, recursiveZipper);
                } catch (Exception e) {
                    System.out.println(fullPath + " FAILED: " + e);
                    e.printStackTrace(System.out);
                }


            } else {
                if (pathLower.endsWith(FILE_LOG4J_1)) {
                    log4jProbe[0] = true;
                } else if (pathLower.endsWith(FILE_LOG4J_2)) {
                    log4jProbe[1] = true;
                } else if (pathLower.endsWith(FILE_LOG4J_3)) {
                    log4jProbe[2] = true;
                } else if (pathLower.endsWith(FILE_LOG4J_4)) {
                    log4jProbe[3] = true;
                } else if (pathLower.endsWith(FILE_LOG4J_5)) {
                    log4jProbe[4] = true;
                } else if (pathLower.endsWith(FILE_LOG4J_2_10)) {
                    isLog4j2_10 = true;
                } else if (pathLower.endsWith(FILE_LOG4J_VULNERABLE)) {
                    hasJndiLookup = true;
                    if (containsMatch(bytes, IS_LOG4J_NOT_SAFE_2_12_2)) {
                        isLog4j2_12_2_override = true;
                    } else {
                        isLog4j2_12_2 = true;
                    }
                } else if (pathLower.endsWith(FILE_LOG4J_SAFE_CONDITION1)) {
                    hasJndiManager = true;
                    if (containsMatch(bytes, IS_LOG4J_SAFE_2_15_0)) {
                        isLog4j2_15 = true;
                    } else {
                        isLog4j2_15_override = true;
                    }
                }
            }
        }

        if (conditionsChecked) {
            boolean isLog4j = false;
            boolean isLog4j_2_10_0 = false;
            boolean isLog4j_2_12_2 = false;
            boolean isVulnerable = false;
            boolean isSafe = false;
            if (log4jProbe[0] && log4jProbe[1] && log4jProbe[2] && log4jProbe[3] && log4jProbe[4]) {
                isLog4j = true;
                if (hasJndiLookup) {
                    isVulnerable = true;
                    if (isLog4j2_10) {
                        isLog4j_2_10_0 = true;
                        if (hasJndiManager) {
                            if ((isLog4j2_15 && !isLog4j2_15_override) || (isLog4j2_12_2 && !isLog4j2_12_2_override)) {
                                isSafe = true;
                                isLog4j_2_12_2 = (isLog4j2_12_2 && !isLog4j2_12_2_override);
                            }
                        }
                    }
                }
            }

            StringBuilder buf = new StringBuilder();
            if (isLog4j) {
                buf.append(zipPath).append(" contains Log4J-2.x   ");
                if (isVulnerable) {
                    if (isLog4j_2_10_0) {
                        if (isSafe) {
                            if (isLog4j_2_12_2) {
                                buf.append(">= 2.12.2 _SAFE_ :-)");
                            } else {
                                buf.append(">= 2.15.0 _SAFE_ :-)");
                            }
                        } else {
                            buf.append(">= 2.10.0 _VULNERABLE_ :-(");
                        }
                    } else {
                        buf.append(">= 2.0-beta9 (< 2.10.0) _VULNERABLE_ :-(");
                    }
                } else {
                    buf.append("<= 2.0-beta8 _POTENTIALLY_SAFE_ :-| (or did you already remove JndiLookup.class?) ");
                }
                if (!isSafe) {
                    foundHits = true;
                }
                System.out.println(buf);
            }
        }

        /*
        if (!isZip) {
            File f = new File(zipPath);
            if (f.canRead() && f.length() < 5000000) {
                FileInputStream fin = null;
                try {
                    fin = new FileInputStream(f);
                    byte[] bytes = Bytes.streamToBytes(fin);
                    containsMatch(bytes);
                } catch (IOException ioe) {
                    // System.out.println("FAILED TO READ " + zipPath + ": " + ioe);
                } finally {
                    if (fin != null) {
                        try {
                            fin.close();
                        } catch (IOException ioe) {
                            // swallow close exception
                        }
                    }
                }
            }
        }
         */
    }

    private static boolean containsMatch(byte[] bytes, byte[] needle) {
        int matched = Bytes.kmp(bytes, needle);
        return matched >= 0;
    }

    public static void scan(
            final File zipFile
    ) {
        Zipper myZipper = new Zipper() {
            private FileInputStream fin;
            private ZipInputStream zin;

            public ZipInputStream getFreshZipStream() {
                Util.close(zin, fin);
                try {
                    fin = new FileInputStream(zipFile);
                    int pos = getZipStart(fin);
                    if (pos < 0) {
                        fin.close();
                        return null;
                    }
                    fin.close();
                    fin = new FileInputStream(zipFile);
                    // Advance to beginning of zip...
                    for (int i = 0; i < pos; i++) {
                        int c = fin.read();
                        if (c < 0) {
                            throw new RuntimeException("Zip closed early i=" + i + " - should be impossible");
                        }
                    }

                    zin = new ZipInputStream(fin);
                    return zin;
                } catch (IOException ioe) {
                    throw new RuntimeException(ioe);
                }
            }

            public void close() {
                Util.close(zin, fin);
            }
        };

        try {
            String zip = zipFile.getPath();
            findLog4jRecursive(zip, myZipper);
        } catch (Exception e) {
            System.out.println(zipFile.getPath() + " FAILED: " + e);
            e.printStackTrace(System.out);
        } finally {
            myZipper.close();
        }
    }

    private static int getZipStart(InputStream in) {
        int pos = -1;
        try {
            int[] fourBytes = pop4(in);
            pos = 0;
            if (!isZipSentinel(fourBytes)) {
                int read = nextByte(fourBytes, in);
                pos++;
                while (read >= 0) {
                    if (isZipSentinel(fourBytes)) {
                        break;
                    }
                    read = nextByte(fourBytes, in);
                    pos++;
                }
                if (read < 0) {
                    pos = -1;
                }
            }
        } catch (IOException ioe) {
            pos = -1;
        }
        return pos;
    }

    private static void analyze(File f) {
        Path p = null;
        try {
            p = f.toPath();
        } catch (Exception e) {
            // oh well
            if (verbose) {
                System.err.println("Cannot determine if " + f.getPath() + " is symlink: " + e);
            }
        }
        boolean isSymlink = p != null && Files.isSymbolicLink(p);
        boolean cannotRead = !f.canRead();
        if (isSymlink || cannotRead) {
            return;
        }

        if (f.isDirectory()) {
            File[] fileList = f.listFiles();
            if (fileList != null) {
                Arrays.sort(fileList, FILES_ORDER_BY_NAME);
                for (File ff : fileList) {
                    analyze(ff);
                }
            }
        } else {
            if (f.isFile() || f.isHidden()) {
                scan(f);
            } else {
                if (verbose) {
                    System.err.println("-- Skipping " + f.getPath() + " - Not a regular file.");
                }
            }
        }
    }

}
