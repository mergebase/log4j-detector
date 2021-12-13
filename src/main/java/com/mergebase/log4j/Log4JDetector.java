package com.mergebase.log4j;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Log4JDetector {

    private static final String FILE_LOG4J_1 = "core/LogEvent.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_2 = "core/Appender.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_3 = "core/Filter.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_4 = "core/Layout.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_5 = "core/LoggerContext.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_2_10 = "appender/nosql/NoSqlAppender.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_VULNERABLE = "JndiLookup.class".toUpperCase(Locale.ROOT);
    private static final String FILE_LOG4J_SAFE_CONDITION1 = "JndiManager.class".toUpperCase(Locale.ROOT);

    private static byte[] IS_LOG4J_SAFE_CONDITION2 = Bytes.fromString("Invalid JNDI URI - {}");

    private static boolean verbose = false;
    private static boolean foundHits = false;

    public static void main(String[] args) throws Exception {
        List<String> argsList = new ArrayList<>(Arrays.asList(args));
        Iterator<String> it = argsList.iterator();
        while (it.hasNext()) {
            final String argOrig = it.next();
            if ("--verbose".equals(argOrig)) {
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
            System.out.println("Usage: java -jar log4j-detector-2021.12.13.jar [--verbose] [paths to scan...]");
            System.out.println();
            System.out.println("Exit codes:  0 = No vulnerable Log4J versions found.");
            System.out.println("             2 = At least one vulnerable Log4J version found.");
            System.out.println();
            System.out.println("About - MergeBase log4j detector (version 2021.12.13)");
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

    private static void findLog4jRecursive(
            final String zipPath, final Zipper zipper
    ) {

        ZipEntry ze;
        ZipInputStream zin;

        // 1st pass... look for archives inside the archive
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
            System.out.println("-- Problem: " + zipPath + " - NULL!?!");
            return;
        }

        if (verbose) {
            System.err.println("-- Examining " + zipPath + "... ");
        }
        boolean isZip = false;
        boolean conditionsChecked = false;
        boolean[] conditions = new boolean[9];
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
            final String path = ze.getName();
            final String fullPath = zipPath + "!/" + path;
            final String PATH = path.toUpperCase(Locale.ENGLISH);
            boolean isSubZip = PATH.endsWith(".ZIP") || PATH.endsWith(".WAR") || PATH.endsWith(".EAR") || PATH.endsWith(".JAR") || PATH.endsWith(".AAR");
            boolean isClassEntry = PATH.endsWith(".CLASS");

            byte[] b = new byte[0];
            if (isSubZip || isClassEntry) {
                try {
                    b = Bytes.streamToBytes(zin, false);
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
                        public JarInputStream getFreshZipStream() {
                            ByteArrayInputStream bin = new ByteArrayInputStream(bytes);
                            try {
                                return new JarInputStream(bin);
                            } catch (IOException ioe) {
                                throw new RuntimeException("JarInputStream failed - " + ioe, ioe);
                            }
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
                if (PATH.endsWith(FILE_LOG4J_1)) {
                    conditions[0] = true;
                } else if (PATH.endsWith(FILE_LOG4J_2)) {
                    conditions[1] = true;
                } else if (PATH.endsWith(FILE_LOG4J_3)) {
                    conditions[2] = true;
                } else if (PATH.endsWith(FILE_LOG4J_4)) {
                    conditions[3] = true;
                } else if (PATH.endsWith(FILE_LOG4J_5)) {
                    conditions[4] = true;
                } else if (PATH.endsWith(FILE_LOG4J_2_10)) {
                    conditions[5] = true;
                } else if (PATH.endsWith(FILE_LOG4J_VULNERABLE)) {
                    conditions[6] = true;
                } else if (PATH.endsWith(FILE_LOG4J_SAFE_CONDITION1)) {
                    conditions[7] = true;
                    if (containsMatch(bytes)) {
                        conditions[8] = true;
                    }
                }
            }
        }

        if (conditionsChecked) {
            boolean isLog4j = false;
            boolean isLog4j_2_10 = false;
            boolean isVulnerable = false;
            boolean isSafe = false;
            if (conditions[0] && conditions[1] && conditions[2] && conditions[3] && conditions[4]) {
                isLog4j = true;
                if (conditions[6]) {
                    isVulnerable = true;
                    if (conditions[5]) {
                        isLog4j_2_10 = true;
                        if (conditions[7] && conditions[8]) {
                            isSafe = true;
                        }
                    }
                }
            }

            StringBuilder buf = new StringBuilder();
            if (isLog4j) {
                buf.append(zipPath).append(" contains Log4J-2.x   ");
                if (isVulnerable) {
                    if (isLog4j_2_10) {
                        if (isSafe) {
                            buf.append(">= 2.15.0 SAFE :-)");
                        } else {
                            buf.append(">= 2.10.0 _VULNERABLE_ :-(");
                        }
                    } else {
                        buf.append(">= 2.0-beta9 (< 2.10.0) _VULNERABLE_ :-(");
                    }
                } else {
                    buf.append("<= 2.0-beta8 _POTENTIALLY_SAFE_ :-|");
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

    private static boolean containsMatch(byte[] bytes) {
        for (byte[] needle : needles()) {
            int matched = Bytes.kmp(bytes, needle);
            if (matched >= 0) {
                return true;
            }
        }
        return false;
    }

    public static void scan(
            final File zipFile
    ) {

        Zipper myZipper = new Zipper() {
            private FileInputStream fin;
            private BufferedInputStream bin;
            private JarInputStream zin;

            public JarInputStream getFreshZipStream() {
                Util.close(zin, bin, fin);
                try {
                    fin = new FileInputStream(zipFile);
                    bin = new BufferedInputStream(fin);
                    zin = new JarInputStream(bin);
                    return zin;
                } catch (IOException ioe) {
                    throw new RuntimeException(ioe);
                }
            }

            public void close() {
                Util.close(zin, bin, fin);
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

    private static void analyze(File f) {
        boolean isSymlink = Files.isSymbolicLink(f.toPath());
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

    private static Collection<byte[]> needles() {
        return Collections.singleton(IS_LOG4J_SAFE_CONDITION2);
    }
}
