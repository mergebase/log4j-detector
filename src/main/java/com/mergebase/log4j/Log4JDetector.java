/*
 * This file is licensed to the public under the terms of the GNU Public License 3.0
 * (aka GPLv3).
 *
 * To be clear, for the purposes of copyright law, any program ["The Importing Program"] that
 * imports this file (via Java's "import" mechanism or via Java reflection or via any
 * other software technique for importing or referencing functionality) is considered
 * a derivative work of this work, and must also comply with the conditions of the GPLv3
 * license in The Importing Program's totality to be granted a copyright license to this work,
 * and must also use the same definition as defined here for what constitutes a derivative work
 * of itself.
 *
 */
package com.mergebase.log4j;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.mergebase.log4j.VersionComparator.compare;

public class Log4JDetector {

    private static final String POM_PROPERTIES = "log4j-core/pom.properties".toLowerCase(Locale.ROOT);
    private static final String FILE_OLD_LOG4J = "log4j/DailyRollingFileAppender.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_1 = "core/LogEvent.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2 = "core/Appender.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_3 = "core/Filter.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_4 = "core/Layout.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_5 = "core/LoggerContext.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2_10 = "appender/nosql/NoSqlAppender.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_JNDI_LOOKUP = "core/lookup/JndiLookup.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_JNDI_MANAGER = "core/net/JndiManager.".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_JDBC_DSCS = "core/appender/db/jdbc/DataSourceConnectionSource.".toLowerCase(Locale.ROOT);

    private static final String FILE_GONE_LOG4J_2_17 = "core/util/SetUtils.".toLowerCase(Locale.ROOT);

    private static final String ACTUAL_FILE_LOG4J_2 = "core/Appender.class";
    private static final String ACTUAL_FILE_LOG4J_3 = "core/Filter.class";
    private static final String ACTUAL_FILE_LOG4J_4 = "core/Layout.class";
    private static final String ACTUAL_FILE_LOG4J_5 = "core/LoggerContext.class";
    private static final String ACTUAL_FILE_LOG4J_2_10 = "core/appender/nosql/NoSqlAppender.class";
    private static final String ACTUAL_FILE_GONE_LOG4J_2_17 = "core/util/SetUtils.class";
    private static final String ACTUAL_FILE_LOG4J_JNDI_LOOKUP = "core/lookup/JndiLookup.class";
    private static final String ACTUAL_FILE_LOG4J_JNDI_MANAGER = "core/net/JndiManager.class";
    private static final String ACTUAL_FILE_LOG4J_JDBC_DSCS = "core/appender/db/jdbc/DataSourceConnectionSource.class";

    // This occurs in "JndiManager.class" in 2.15.0
    private static final byte[] IS_LOG4J_SAFE_2_15_0 = Bytes.fromString("Invalid JNDI URI - {}");

    // This occurs in "JndiManager.class" in 2.16.0
    private static final byte[] IS_LOG4J_SAFE_2_16_0 = Bytes.fromString("log4j2.enableJndi");

    // This occurs in "JndiLookup.class" in 2.17.0
    private static final byte[] INSIDE_LOG4J_2_17_0 = Bytes.fromString("JNDI must be enabled by setting log4j2.enableJndiLookup=true");

    // This occurs in "JndiLookup.class" before 2.12.2
    private static final byte[] IS_LOG4J_NOT_SAFE_2_12_2 = Bytes.fromString("Error looking up JNDI resource [{}].");

    // This occurs in "JndiManager.class" in 2.3.1
    private static final byte[] IS_LOG4J_SAFE_2_3_1 = Bytes.fromString("Unsupported JNDI URI - {}");

    // This occurs in "DataSourceConnectionSource.class" in 2.17.1 and friends.
    private static final byte[] IS_CVE_2021_44832_SAFE = Bytes.fromString("JNDI must be enabled by setting log4j2.enableJndiJdbc=true");

    private static boolean verbose = false;
    private static boolean debug = false;
    private static boolean json = false;
    private static Set<String> excludes = new TreeSet<String>();
    private static boolean foundHits = false;
    private static boolean foundLog4j1 = false;

    private static File currentDir = null;
    private static String currentPath = null;
    private static boolean printFullPaths = false;

    public static void main(String[] args) throws IOException {
        currentDir = canonicalize(new File("."));
        currentPath = currentDir.getPath();

        List<String> argsList = new ArrayList<String>();
        Collections.addAll(argsList, args);

        Iterator<String> it = argsList.iterator();
        List<String> stdinLines = new ArrayList<String>();
		int argIdx = 0;
        while (it.hasNext()) {
            final String argOrig = it.next().trim();
			System.out.println("Arg #" + argIdx++ + ": " + argOrig);
            if ("--debug".equals(argOrig)) {
                debug = true;
                it.remove();
            } else if ("--verbose".equals(argOrig)) {
                verbose = true;
                it.remove();
            } else if ("--json".equals(argOrig)) {
                json = true;
                it.remove();
            } else if (argOrig.startsWith("--exclude=[")) {
                int x = argOrig.indexOf("]");
                if (x > 0) {
                    it.remove();
                    String json = argOrig.substring("--exclude=".length());
                    Object o = Java2Json.parse(json);
                    if (o instanceof List) {
                        List<Object> list = (List) o;
                        for (Object obj : list) {
                            if (obj != null) {
								
								String excl_canon = canonicalize(new File(String.valueOf(obj))).getPath();
                                excludes.add(excl_canon);
                            }
                        }
                    }
                }
            } else if ("--stdin".equals(argOrig)) {
                it.remove();
                byte[] b = Bytes.streamToBytes(System.in);
                String s = new String(b, Bytes.UTF_8);
                stdinLines = Strings.intoLines(s);
            } else {
                File f;
                if (argOrig.length() == 2 && ':' == argOrig.charAt(1) && Character.isLetter(argOrig.charAt(0))) {
                    f = new File(argOrig + File.separator);
                } else {
                    f = new File(argOrig);
                }
                if (!f.exists()) {
                    System.err.println("Invalid file: [" + f.getPath() + "]");
                    System.exit(102);
                }
            }
        }
        argsList.addAll(stdinLines);

        if (argsList.isEmpty()) {
            System.out.println();
            System.out.println("Usage: java -jar log4j-detector-2021.12.29.jar [--verbose] [--json] [--stdin] [--exclude=X] [paths to scan...]");
            System.out.println();
            System.out.println("  --json       - Output STDOUT results in JSON.  (Errors/warning still emitted to STDERR)");
            System.out.println("  --stdin      - Parse STDIN for paths to explore.");
            System.out.println("  --exclude=X  - Where X is a JSON list containing full paths to exclude. Must be valid JSON.");
            System.out.println();
            System.out.println("                 Example: --exclude='[\"/dev\", \"/media\", \"Z:\\TEMP\"]' ");
            System.out.println();
            System.out.println("Exit codes:  0 = No vulnerable Log4J versions found.");
            System.out.println("             1 = At least one legacy Log4J 1.x version found.");
            System.out.println("             2 = At least one vulnerable Log4J 2.x version found.");
            System.out.println();
            System.out.println("About - MergeBase log4j detector (version 2021.12.29)");
            System.out.println("Docs  - https://github.com/mergebase/log4j-detector ");
            System.out.println("(C) Copyright 2021 Mergebase Software Inc. Licensed to you via GPLv3.");
            System.out.println();
            System.exit(100);
        }

        System.err.println("-- github.com/mergebase/log4j-detector v2021.12.29 (by mergebase.com) analyzing paths (could take a while).");
        System.err.println("-- Note: specify the '--verbose' flag to have every file examined printed to STDERR.");
        if (json) {
            System.out.println("{\"hits\":[");
        }
        for (String arg : argsList) {
            File dir;
            if (arg.length() == 2 && ':' == arg.charAt(1) && Character.isLetter(arg.charAt(0))) {
                dir = new File(arg + File.separator);
            } else {
                dir = new File(arg);
            }
            analyze(dir);
        }
        if (json) {
            System.out.println("{\"_THE_END_\":true}]}");
        }
        if (foundHits) {
            System.exit(2);
        } else if (foundLog4j1) {
            System.exit(1);
        } else {
            System.err.println("-- No vulnerable Log4J 2.x samples found in supplied paths: " + argsList);
            System.err.println("-- Congratulations, the supplied paths are not vulnerable to CVE-2021-44228 or CVE-2021-45046 !  :-) ");
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
        File f = new File("blah");
        return four[3];
    }

    private static boolean isZipSentinel(int[] chunk) {
        return chunk[0] == 0x50 && chunk[1] == 0x4B && chunk[2] == 3 && chunk[3] == 4;
    }

    private static final Comparator<File> FILES_ORDER_BY_NAME = new Comparator<File>() {
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

    /**
     * @param fileName name to examine for type
     * @return 0 == zip, 1 == class, 2 = log4j-core/pom.properties, -1 = who knows...
     */
    private static int fileType(String fileName) {
        int c = fileName.lastIndexOf('.');
        if (c >= 0) {
            String suffix = fileName.substring(c + 1);

            // Special logic for "log4j-core/pom.properties" last-resort version source.
            if ("properties".equalsIgnoreCase(suffix)) {
                String lower = fileName.toLowerCase(Locale.ROOT);
                if (lower.endsWith(POM_PROPERTIES)) {
                    return 2;
                }
            } else if ("class".equalsIgnoreCase(suffix)) {
                return 1;
            } else if ("zip".equalsIgnoreCase(suffix)
                    || "jpi".equalsIgnoreCase(suffix)
                    || "hpi".equalsIgnoreCase(suffix)
                    || suffix.endsWith("ar")) {
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
            try {
                zin = zipper.getFreshZipStream();
            } catch (Exception e) {
                System.err.println("-- Problem: " + zipPath + " - " + e);
                if (verbose) {
                    e.printStackTrace(System.err);
                }
                return;
            }
            if (zin == null) {
                if (fileType(zipPath) == 0) {
                    System.err.println("-- Problem: " + zipPath + " - Not actually a zip!?! (no magic number)");
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

            boolean conditionsChecked = false;
            boolean[] log4jProbe = new boolean[5];
            boolean isLog4j2_10 = false;
            boolean hasJndiLookup = false;
            boolean hasJndiManager = false;
            boolean hasJdbcJndiDisabled = false;
            boolean hasSetUtils = false;
            boolean isLog4J1_X = false;
            boolean isLog4j2_15 = false;
            boolean isLog4j2_16 = false;
            boolean isLog4j2_17 = false;
            boolean isLog4j2_15_override = false;
            boolean isLog4j2_12_2 = false;
            boolean isLog4j2_12_3 = false;
            boolean isLog4j2_3_1 = false;
            boolean isLog4j2_12_2_override = false;
            byte[] pomProperties = null;
            String pomPath = null;
            ZipEntry ze;
            while (true) {
                try {
                    ze = zin.getNextEntry();
                } catch (Exception oops) {
                    System.err.println("-- Problem " + zipPath + " - " + oops);
                    if (verbose) {
                        oops.printStackTrace(System.err);
                    }
                    return;
                }
                if (ze == null) {
                    break;
                }
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
                boolean isPomProperties = fileType == 2;
                boolean needClassBytes = false;
                final boolean isJndiLookup = pathLower.contains(FILE_LOG4J_JNDI_LOOKUP);
                final boolean isJndiManager = pathLower.contains(FILE_LOG4J_JNDI_MANAGER);
                final boolean isJdbcConnManager = pathLower.contains(FILE_LOG4J_JDBC_DSCS);

                if (isPomProperties || isJndiLookup || isJndiManager || isJdbcConnManager) {
                    needClassBytes = true;
                }

                if (debug) {
                    System.err.println("-- DEBUG - " + fullPath + " size=" + zipEntrySize + " isZip=" + isSubZip + " isClass=" + isClassEntry);
                }
                byte[] b = new byte[0];
                if (isSubZip || needClassBytes) {
                    try {
                        b = Bytes.streamToBytes(zin, false, zipEntrySize + 1);
                    } catch (Exception e) {
                        System.err.println("-- Problem - could not extract " + fullPath + " (size=" + zipEntrySize + ") - " + e);
                        if (verbose) {
                            e.printStackTrace(System.err);
                        }
                        continue;
                    }
                }
                final byte[] bytes = b;

                if (isSubZip) {
                    try {
                        Zipper recursiveZipper = new Zipper() {

                            private ByteArrayInputStream bin = new ByteArrayInputStream(bytes);

                            public ZipInputStream getFreshZipStream() {
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
                        System.err.println(fullPath + " FAILED: " + e);
                        e.printStackTrace(System.err);
                    }


                } else {
                    if (pathLower.endsWith(POM_PROPERTIES)) {
                        pomProperties = bytes;
                        pomPath = "!/" + path;
                    } else if (isJdbcConnManager) {
                        if (containsMatch(bytes, IS_CVE_2021_44832_SAFE)) {
                            hasJdbcJndiDisabled = true;
                        }
                    } else if (pathLower.contains(FILE_OLD_LOG4J)) {
                        isLog4J1_X = true;
                    } else if (pathLower.contains(FILE_LOG4J_1)) {
                        log4jProbe[0] = true;
                    } else if (pathLower.contains(FILE_LOG4J_2)) {
                        log4jProbe[1] = true;
                    } else if (pathLower.contains(FILE_LOG4J_3)) {
                        log4jProbe[2] = true;
                    } else if (pathLower.contains(FILE_LOG4J_4)) {
                        log4jProbe[3] = true;
                    } else if (pathLower.contains(FILE_LOG4J_5)) {
                        log4jProbe[4] = true;
                    } else if (pathLower.contains(FILE_LOG4J_2_10)) {
                        isLog4j2_10 = true;
                    } else if (pathLower.contains(FILE_GONE_LOG4J_2_17)) {
                        hasSetUtils = true;
                    } else if (isJndiLookup) {
                        hasJndiLookup = true;
                        if (containsMatch(bytes, INSIDE_LOG4J_2_17_0)) {
                            isLog4j2_17 = true;
                        } else if (containsMatch(bytes, IS_LOG4J_NOT_SAFE_2_12_2)) {
                            isLog4j2_12_2_override = true;
                        } else {
                            isLog4j2_12_2 = true;
                        }
                    } else if (isJndiManager) {
                        hasJndiManager = true;
                        if (containsMatch(bytes, IS_LOG4J_SAFE_2_15_0)) {
                            isLog4j2_15 = true;
                            if (containsMatch(bytes, IS_LOG4J_SAFE_2_16_0)) {
                                isLog4j2_16 = true;
                            }
                        } else {
                            isLog4j2_15_override = true;
                        }
                        if (containsMatch(bytes, IS_LOG4J_SAFE_2_3_1)) {
                            isLog4j2_3_1 = true;
                        }
                    }
                }
            }


            if (conditionsChecked) {
                if (!log4jProbe[0] || !log4jProbe[1] || !log4jProbe[2] || !log4jProbe[3] || !log4jProbe[4]) {
                    if (pomProperties != null) {
                        System.err.println("-- Warning: " + zipPath + " does not contain Log4J bytecode, but claims it does (" + pomPath + ")");
                        ByteArrayInputStream byteIn = new ByteArrayInputStream(pomProperties);
                        Properties p = new Properties();
                        try {
                            p.load(byteIn);
                            String version = p.getProperty("version");
                            if (version != null) {
                                boolean isLog4j2 = compare("2", version) <= 0;
                                if (isLog4j2) {
                                    log4jProbe = new boolean[]{true, true, true, true, true};
                                    hasJndiLookup = compare("2.0-beta9", version) <= 0;
                                    hasJndiManager = compare("2.1", version) <= 0;
                                    isLog4j2_10 = compare("2.10.0", version) <= 0;
                                    isLog4j2_12_2 = version.startsWith("2.12.") && compare("2.12.2", version) <= 0;
                                    if (isLog4j2_12_2) {
                                        isLog4j2_12_2_override = false;
                                    }
                                    isLog4j2_15 = version.startsWith("2.15.");
                                    isLog4j2_16 = version.startsWith("2.16.");
                                    isLog4j2_17 = compare("2.17.0", version) <= 0;
                                    if (isLog4j2_15 || isLog4j2_16 || isLog4j2_17) {
                                        isLog4j2_15_override = false;
                                    }
                                }
                            }
                        } catch (IOException ioe) {
                            // invalid properties file!?!
                        }
                    }
                }


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
                                if (isLog4j2_17 || (isLog4j2_15 && !isLog4j2_15_override) || (isLog4j2_12_2 && !isLog4j2_12_2_override)) {
                                    isSafe = true;
                                    isLog4j_2_12_2 = (isLog4j2_12_2 && !isLog4j2_12_2_override);
                                    if (isLog4j2_17 && hasSetUtils) {
                                        isLog4j2_12_3 = true;
                                        isLog4j2_17 = false;
                                    }
                                }
                            }
                        }
                    }
                }

                StringBuilder buf = new StringBuilder();
                if (isLog4j) {
                    if (isLog4J1_X) {
                        buf.append(" contains Log4J-1.x AND Log4J-2.x _CRAZY_   ");
                        foundLog4j1 = true;
                    } else {
                        buf.append(" contains Log4J-2.x   ");
                    }
                    if (isVulnerable) {
                        if (isLog4j_2_10_0) {
                            if (isSafe) {
                                if (isLog4j_2_12_2) {
                                    buf.append("== 2.12.2 _OKAY_");
                                    foundHits = true;
                                } else {
                                    if (isLog4j2_12_3) {
                                        if (hasJdbcJndiDisabled) {
                                            buf.append("== 2.12.4 _SAFE_");
                                        } else {
                                            buf.append("== 2.12.3 _OKAY_");
                                            foundHits = true;
                                        }
                                    } else if (isLog4j2_17) {
                                        if (hasJdbcJndiDisabled) {
                                            buf.append(">= 2.17.1 _SAFE_");
                                        } else {
                                            buf.append("== 2.17.0 _OKAY_");
                                            foundHits = true;
                                        }
                                    } else if (isLog4j2_16) {
                                        buf.append("== 2.16.0 _OKAY_");
                                        foundHits = true;
                                    } else {
                                        buf.append("== 2.15.0 _OKAY_");
                                        foundHits = true;
                                    }
                                }
                            } else {
                                buf.append(">= 2.10.0 _VULNERABLE_");
                            }
                        } else {
                            if (isLog4j2_3_1) {
                                isSafe = true;
                                if (hasJdbcJndiDisabled) {
                                    buf.append("== 2.3.2 _SAFE_");
                                } else {
                                    buf.append("== 2.3.1 _OKAY_");
                                    foundHits = true;
                                }
                            } else {
                                buf.append(">= 2.0-beta9 (< 2.10.0) _VULNERABLE_");
                            }
                        }
                    } else {
                        buf.append("<= 2.0-beta8 _POTENTIALLY_SAFE_ (Did you remove JndiLookup.class?)");
                    }
                    if (!isSafe) {
                        foundHits = true;
                    }
                    System.out.println(prepareOutput(zipPath, buf));
                } else if (isLog4J1_X) {
                    buf.append(" contains Log4J-1.x   <= 1.2.17 _OLD_");
                    foundLog4j1 = true;
                    System.out.println(prepareOutput(zipPath, buf));
                }
            }
        } finally {
            if (zipper != null) {
                zipper.close();
            }
        }
    }

    private static String prepareOutput(String zipPath, StringBuilder buf) {
        if (!printFullPaths) {
            if (zipPath.startsWith(currentPath)) {
                zipPath = zipPath.substring(currentPath.length());
                if (zipPath.startsWith(File.separator)) {
                    zipPath = zipPath.substring(1);
                }
            } else {
                printFullPaths = true;
            }
        }
        if (json) {
            String msg = buf.toString().trim();
            int x = msg.lastIndexOf(" _");
            String status = "_UNKNOWN_";
            if (x >= 0) {
                status = msg.substring(x).trim();
                msg = msg.substring(0, x).trim();
            }
            Map<String, String> m = new LinkedHashMap<String, String>();
            m.put(status, zipPath);
            m.put("info", msg);
            return Java2Json.format(m) + ",";
        } else {
            return zipPath + buf;
        }
    }

    private static boolean containsMatch(byte[] bytes, byte[] needle) {
        int matched = Bytes.kmp(bytes, needle);
        return matched >= 0;
    }

    private static void scan(
            final File zipFile
    ) {
        Zipper myZipper = new Zipper() {
            private FileInputStream fin;
            private BufferedInputStream bin;
            private ZipInputStream zin;

            public ZipInputStream getFreshZipStream() {
                Util.close(zin, bin, fin);
                try {
                    fin = new FileInputStream(zipFile);
                    bin = new BufferedInputStream(fin);
                    if (startsWithZipMagic(bin)) {
                        zin = new ZipInputStream(bin);
                        return zin;
                    } else {
                        int pos = getZipStart(bin);
                        if (pos < 0) {
                            bin.close();
                            fin.close();
                            return null;
                        }
                        bin.close();
                        fin.close();

                        fin = new FileInputStream(zipFile);
                        bin = new BufferedInputStream(fin);
                        // Advance to beginning of zip...
                        for (int i = 0; i < pos; i++) {
                            int c = bin.read();
                            if (c < 0) {
                                throw new RuntimeException("Zip closed early i=" + i + " - should be impossible");
                            }
                        }
                        zin = new ZipInputStream(bin);
                        return zin;
                    }
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
            System.err.println("-- Problem: " + zipFile.getPath() + " FAILED: " + e);
            e.printStackTrace(System.err);
        } finally {
            myZipper.close();
        }
    }

    private static boolean startsWithZipMagic(BufferedInputStream in) {
        in.mark(4);
        try {
            int[] fourBytes = pop4(in);
            return isZipSentinel(fourBytes);
        } catch (IOException ioe) {
            return false;
        } finally {
            try {
                in.reset();
            } catch (IOException ioe) {
                throw new RuntimeException("BufferedInputStream.reset() failed: " + ioe);
            }
        }
    }

    private static int getZipStart(InputStream in) {
        int pos;
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

    private static final HashSet<Long> visited = new HashSet<Long>();

    private static File canonicalize(File f) {
        try {
            f = f.getCanonicalFile();
        } catch (Exception e) {
            // oh well
            if (verbose) {
                System.err.println("f.getCanonicalFile() failed: " + f.getPath() + " - " + e);
            }
            f = f.getAbsoluteFile();
        }
        return f;
    }

    private static void analyze(File f) {
        f = canonicalize(f);

        // Hopefully this stops symlink cycles.
        // Using CRC-64 of path to save on memory (since we're storing *EVERY* path we come across).
        String path = f.getPath();
        if (excludes.contains(path)) {
            System.err.println("-- Info: Skipping [" + path + "] because --excludes mentions it.");
            return;
        }
        File parent = f.getParentFile();
        while (parent != null) {
            String parentPath = parent.getPath();
            if (excludes.contains(parentPath)) {
                System.err.println("-- Info: Skipping [" + path + "] because --excludes mentions it.");
                return;
            }
            parent = parent.getParentFile();
        }
        long crc = CRC64.hash(path);
        if (visited.contains(crc)) {
            return;
        } else {
            visited.add(crc);
        }

        if (f.isDirectory()) {
            if (!f.canRead()) {
                System.err.println("-- Problem: no permission to read directory - " + f.getPath());
                return;
            }

            File[] fileList = f.listFiles();
            if (fileList != null) {
                Arrays.sort(fileList, FILES_ORDER_BY_NAME);
                for (File ff : fileList) {
                    analyze(ff);
                }
            }
        } else {
            if (f.isFile() || f.isHidden()) {
                int fileType = fileType(f.getName());
                if (0 == fileType) {
                    if (!f.canRead()) {
                        System.err.println("-- Problem: no permission to read contents of zip file - " + f.getPath());
                        return;
                    }
                    scan(f);
                } else if (1 == fileType) {
                    String currentPathLower = f.getPath().toLowerCase(Locale.ROOT);
                    boolean isLog4J_1_X = currentPathLower.contains(FILE_OLD_LOG4J);
                    boolean maybe = false;
                    if (isLog4J_1_X) {
                        StringBuilder buf = new StringBuilder();
                        String grandParent = f.getParentFile().getParent();
                        buf.append(" contains Log4J-1.x   <= 1.2.17 _OLD_ :-|");
                        System.out.println(prepareOutput(grandParent, buf));
                    } else {
                        maybe = currentPathLower.contains(FILE_LOG4J_1);
                    }
                    if (maybe) {
                        boolean isVulnerable = false;
                        boolean isLog4J_2_3_1 = false;
                        boolean isLog4J_2_10 = false;
                        boolean isLog4J_2_12_2 = false;
                        boolean isLog4J_2_15 = false;
                        boolean isLog4J_2_16 = false;
                        boolean isLog4J_2_17 = false;

                        byte[] jndiManagerBytes = null;
                        File jndiManager = new File(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_JNDI_MANAGER);
                        final boolean jndiManagerExists = jndiManager.exists();
                        if (jndiManager.canRead()) {
                            jndiManagerBytes = Bytes.fileToBytes(jndiManager);
                        }

                        boolean hasJdbcJndiDisabled = false;
                        File jdbcConn = new File(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_JDBC_DSCS);
                        if (jdbcConn.canRead()) {
                            byte[] jdbcConnBytes = Bytes.fileToBytes(jdbcConn);
                            if (containsMatch(jdbcConnBytes, IS_CVE_2021_44832_SAFE)) {
                                hasJdbcJndiDisabled = true;
                            }
                        }

                        boolean hasSetUtils = exists(f.getParent() + "/../" + ACTUAL_FILE_GONE_LOG4J_2_17);
                        if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_2)) {
                            if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_3)) {
                                if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_4)) {
                                    if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_5)) {
                                        if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_JNDI_LOOKUP)) {
                                            isVulnerable = true;
                                            if (exists(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_2_10)) {
                                                isLog4J_2_10 = true;

                                                // Check for 2.12.2...
                                                File jndiLookup = new File(f.getParent() + "/../" + ACTUAL_FILE_LOG4J_JNDI_LOOKUP);
                                                if (jndiLookup.canRead()) {
                                                    byte[] bytes = Bytes.fileToBytes(jndiLookup);
                                                    if (!containsMatch(bytes, IS_LOG4J_NOT_SAFE_2_12_2)) {
                                                        isLog4J_2_12_2 = true;
                                                    } else if (containsMatch(bytes, INSIDE_LOG4J_2_17_0)) {
                                                        isLog4J_2_17 = true;
                                                    }
                                                } else {
                                                    System.err.println("-- Problem: no permission to read file - " + jndiLookup.getPath() + " (required to determine if 2.12.2, will assume not)");
                                                }

                                                if (jndiManagerExists) {
                                                    if (jndiManagerBytes != null) {
                                                        if (containsMatch(jndiManagerBytes, IS_LOG4J_SAFE_2_15_0)) {
                                                            isLog4J_2_15 = true;
                                                            if (containsMatch(jndiManagerBytes, IS_LOG4J_SAFE_2_16_0)) {
                                                                isLog4J_2_16 = true;
                                                            }
                                                            foundHits = true;

                                                        } else if (!isLog4J_2_17) {
                                                            foundHits = true;
                                                        }
                                                    }
                                                } else {
                                                    System.err.println("-- Problem: no permission to read file - " + jndiManager.getPath() + " (required to determine if 2.16.0, will assume not)");
                                                }

                                            } else {
                                                if (jndiManagerBytes != null && containsMatch(jndiManagerBytes, IS_LOG4J_SAFE_2_3_1)) {
                                                    isLog4J_2_3_1 = true;
                                                } else {
                                                    foundHits = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        StringBuilder buf = new StringBuilder();
                        buf.append(" contains Log4J-2.x   ");
                        if (isVulnerable) {
                            if (isLog4J_2_10) {
                                if (isLog4J_2_17) {
                                    if (hasSetUtils) {
                                        if (hasJdbcJndiDisabled) {
                                            buf.append("== 2.12.4 _SAFE_");
                                        } else {
                                            buf.append("== 2.12.3 _OKAY_");
                                            foundHits = true;
                                        }
                                    } else {
                                        if (hasJdbcJndiDisabled) {
                                            buf.append(">= 2.17.1 _SAFE_");
                                        } else {
                                            buf.append("== 2.17.0 _OKAY_");
                                            foundHits = true;
                                        }
                                    }
                                } else if (isLog4J_2_15) {
                                    foundHits = true;
                                    if (isLog4J_2_16) {
                                        buf.append("== 2.16.0 _OKAY_");
                                    } else {
                                        buf.append("== 2.15.0 _OKAY_");
                                    }
                                } else {
                                    foundHits = true;
                                    if (isLog4J_2_12_2) {
                                        buf.append("== 2.12.2 _OKAY_");
                                    } else {
                                        buf.append(">= 2.10.0 _VULNERABLE_");
                                    }
                                }
                            } else {
                                if (isLog4J_2_3_1) {
                                    if (hasJdbcJndiDisabled) {
                                        buf.append("== 2.3.2 _SAFE_");
                                    } else {
                                        buf.append("== 2.3.1 _OKAY_");
                                        foundHits = true;
                                    }
                                } else {
                                    buf.append(">= 2.0-beta9 (< 2.10.0) _VULNERABLE_");
                                    foundHits = true;
                                }
                            }
                        } else {
                            buf.append("<= 2.0-beta8 _POTENTIALLY_SAFE_ (Did you remove JndiLookup.class?)");
                        }
                        System.out.println(prepareOutput(f.getParentFile().getParent(), buf));
                    }
                } else if (verbose) {
                    System.err.println("-- Skipping " + f.getPath() + " - Not a zip/jar/war file.");
                }
            } else {
                if (verbose) {
                    System.err.println("-- Skipping " + f.getPath() + " - Not a regular file.");
                }
            }
        }

    }

    private static boolean exists(String s) {
        File f = new File(s);
        return f.exists() && f.isFile();
    }

}
