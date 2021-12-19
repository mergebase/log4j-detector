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

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * A total ordering on version numbers that tends to match what humans expect
 * (e.g., "1.2" &lt; "1.2.3alpha99" &lt; "1.2.3beta3" &lt; "1.2.3rc1" &lt; "1.2.3" &lt; "1.2.11" ).
 */
public class VersionComparator {

    static boolean DEBUG = false;

    /**
     * Splits version number by dot.
     * For example: split("major.minor.point") returns: ["major", "minor", "point", ""]
     * <p>
     * Always ends with a final empty-string. Has a few special rules in the split logic to help canonicalize
     * version numbers to aid with comparisons.  For example "1.2.alpha" will return the same split as "1.2alpha",
     * and "v1.2.3" returns ["1", "2", "3", ""] (drops the "v" prefix).
     *
     * @param version version-number to split
     * @return String[] array of the version-number split into its composite parts, ends with empty-string.
     */
    public static String[] split(String version) {

        // truncate version string after first whitespace encountered
        version = version != null ? version.trim() : "";
        int a = indexFix(version.indexOf(' '), version);
        int b = indexFix(version.indexOf('\n'), version);
        int c = indexFix(version.indexOf('\r'), version);
        int d = indexFix(version.indexOf('\t'), version);
        a = Math.min(a, Math.min(b, Math.min(c, d)));
        version = version.substring(0, a);

        // treat ':' same as '.'
        version = version.replace(':', '.');

        // Special handling for "v1.2.3" style version numbers.
        if (version.startsWith("v.") || version.startsWith("V.")) {
            version = version.substring(2);
        } else if (version.startsWith("v") || version.startsWith("V")) {
            version = version.substring(1);
        }

        String[] v1 = version.split("\\.+");

        // In cases liked "1.2.alpha.3" change it to "1.2.alpha3".
        // (pure "pre-release" words are concatenated to next element).
        List<String> list = new ArrayList<String>(v1.length);
        for (int i = 0; i < v1.length; i++) {
            String current = v1[i];
            String prev = i > 0 ? v1[i - 1] : null;
            boolean prevIsDigits = Strings.containsOnlyDigits(prev);
            boolean prevIsPreRelease = VersionComparator.calculateScore(prev, i == v1.length - 1) < 0;
            boolean currentIsDigits = Strings.containsOnlyDigits(current);
            if (i > 0 && !prevIsDigits && currentIsDigits && prevIsPreRelease) {
                int lastIndex = list.size() - 1;
                String last = list.get(lastIndex);
                list.set(lastIndex, last + current);
            } else {
                list.add(current);
            }
        }

        String[] adjusted = new String[list.size()];
        adjusted = list.toArray(adjusted);

        // In cases liked "1.2.alpha" change it to "1.2alpha".
        // (pure pre-release words are concatenated to previous element).
        list = new ArrayList<String>(adjusted.length);
        for (int i = 0; i < adjusted.length; i++) {
            String current = adjusted[i];
            String prev = i > 0 ? adjusted[i - 1] : null;
            boolean prevIsLetters = Strings.containsOnlyLetters(prev);
            boolean currentIsLetters = Strings.containsOnlyLetters(current);
            boolean currentIsPreRelease = VersionComparator.calculateScore(current, i == v1.length - 1) < 0;
            if (i > 0 && !prevIsLetters && currentIsLetters && currentIsPreRelease) {
                int lastIndex = list.size() - 1;
                String last = list.get(lastIndex);
                list.set(lastIndex, last + current);
            } else {
                list.add(current);
            }
        }
        list.add("");

        adjusted = new String[list.size()];
        adjusted = list.toArray(adjusted);
        return adjusted;
    }

    public static String trimReleaseDecorator(String s) {
        if (s != null) {
            s = s.replace(':', '.');
            String[] split = split(s);
            if (split.length > 2) {
                String suffix = split[split.length - 2];
                int score = calculateScore(suffix, true);
                if (score == 1) {
                    StringBuilder join = new StringBuilder(s.length());
                    for (int i = 0; i < split.length - 2; i++) {
                        join.append(split[i]).append('.');
                    }
                    if (join.length() > 0) {
                        join.deleteCharAt(join.length() - 1);
                    }
                    return join.toString();
                }
            }
        }
        return s;
    }

    private static String[] subSplit(String s) {
        List<String> split = new ArrayList<String>();
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((i == 0 && c == '-') || Strings.isLetterOrDigit(c)) {
                buf.append(c);
            } else {
                if (buf.length() > 0) {
                    split.add(buf.toString());
                    buf = new StringBuilder();
                }
            }
        }
        if (buf.length() > 0) {
            split.add(buf.toString());
        }
        String[] result = new String[split.size()];
        return split.toArray(result);
    }

    public static Comparator<String> comparatorBySimilarity(final String anchor) {
        return new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                int i1 = similarity(anchor, o1);
                int i2 = similarity(anchor, o2);
                return Integer.valueOf(i1).compareTo(i2);
            }
        };
    }

    public static int similarity(String s1, String s2) {
        int similarity = -1;
        if (s1 == null && s2 == null) {
            return Integer.MAX_VALUE;
        } else if (s1 == null || s2 == null) {
            return Integer.MIN_VALUE;
        }
        if (s1.equals(s2)) {
            return Integer.MAX_VALUE;
        }
        if ("".equals(s1) || "".equals(s2)) {
            return -1;
        }

        String[] split1 = split(s1);
        String[] split2 = split(s2);
        for (int i = 0; i < Math.min(split1.length, split2.length); i++) {
            similarity = i;
            String test1 = split1[i];
            String test2 = split2[i];
            if (!test1.equals(test2)) {
                break;
            }
        }
        return similarity;
    }

    private static int indexFix(int x, String s) {
        return x < 0 ? s.length() : x;
    }

    /**
     * If 1st digit of string is digit, truncate string
     * after 1st non-digit.
     */
    private static String numerify(String s) {
        s = s != null ? s.trim() : "";
        if (s.length() > 0) {
            char c = s.charAt(0);
            if (c == '-' || isDigit(c)) {
                for (int i = 1; i < s.length(); i++) {
                    c = s.charAt(i);
                    if (!isDigit(c)) {
                        return s.substring(0, i);
                    }
                }
            }
        }
        return s;
    }

    interface SerializableComparator<T> extends Comparator<T>, Serializable {
    }

    public final static SerializableComparator<String> COMPARE_VERSION_STRINGS = new SerializableComparator<String>() {
        public int compare(String v1, String v2) {
            if (v1 != null && v1.equals(v2)) {
                return 0;
            }

            int c = 0;
            String[] ver1 = new String[]{};
            String[] ver2 = ver1;
            try {
                if (anyIsNull(v1, v2)) {
                    c = compareNulls(v1, v2);
                } else {
                    ver1 = split(v1);
                    ver2 = split(v2);

                    boolean done = false;
                    final int end = Math.min(ver1.length, ver2.length);
                    for (int i = 0; i < end; i++) {
                        final boolean isLastWord = (i == end - 1);
                        final String s1 = ver1[i];
                        final String s2 = ver2[i];

                        // Don't run the "NUMERIFIED" comparison for the final
                        // comparison if either String is empty at this point.
                        if (isLastWord) {
                            if ("".equals(s1) || "".equals(s2)) {
                                break;
                            }
                        }

                        // If either candidate starts with a "pre-release" word, abort
                        // NUMERIFIED comparison.  (But proceed if BOTH start this way).
                        if (startsWithPreReleaseWord(s1) != startsWithPreReleaseWord(s2)) {
                            break;
                        }

                        String n1 = numerify(s1);
                        String n2 = numerify(s2);

                        c = alphaNumericCompare(n1, n2, isLastWord);
                        if (c != 0) {
                            done = true;
                            break;
                        }
                    }

                    out:
                    if (!done) {
                        for (int i = 0; i < end; i++) {
                            final boolean isLastWord = (i == end - 1);
                            final String[] sub1 = subSplit(ver1[i]);
                            final String[] sub2 = subSplit(ver2[i]);
                            int subEnd = Math.min(sub1.length, sub2.length);

                            if (DEBUG) {
                                System.out.println("SUBS - " + Arrays.toString(sub1) + " vs. " + Arrays.toString(sub2));
                            }

                            for (int j = 0; j < subEnd; j++) {
                                final String s1 = sub1[j];
                                final String s2 = sub2[j];
                                c = alphaNumericCompare(s1, s2, isLastWord);
                                if (c != 0) {
                                    done = true;
                                    break out;
                                }
                            }

                            if (sub1.length != sub2.length) {
                                c = Integer.valueOf(sub1.length).compareTo(sub2.length);

                                if (Math.abs(sub1.length - sub2.length) == 1) {
                                    String extraBit = sub1.length > sub2.length ? sub1[sub1.length - 1] : sub2[sub2.length - 1];
                                    String[] words = splitIntoAlphasAndNums(extraBit);

                                    // Catch situation where we're comparing: "1.2" vs. "1.2.alpha5".
                                    // Even though "1.2.alpha5" has more dots, it's actually smaller.
                                    if (!startsWithDigit(words[0])) {
                                        int min = minWordScore(words, true);
                                        if (min < 0) {
                                            c = -c;
                                        }
                                    }
                                }

                                done = true;
                                break out;
                            }
                        }
                    }

                    if (!done && ver1.length != ver2.length) {

                        // if they are off by 1..
                        if (ver1.length + 1 == ver2.length || ver1.length == ver2.length + 1) {
                            String extraBit = ver1.length > ver2.length ? ver1[ver1.length - 2] : ver2[ver2.length - 2];
                            if (1 != calculateScore(extraBit, true)) {
                                c = Integer.valueOf(ver1.length).compareTo(ver2.length);
                            }
                        } else {
                            c = Integer.valueOf(ver1.length).compareTo(ver2.length);
                        }
                        done = true;
                    }

                    // Final resort comparison - lexicographic.
                    if (!done) {
                        for (int i = 0; i < end; i++) {
                            final String s1 = Strings.stripLeadingZeroes(ver1[i], 0);
                            final String s2 = Strings.stripLeadingZeroes(ver2[i], 0);
                            c = s1.compareToIgnoreCase(s2);
                            if (c == 0) {
                                c = s1.compareTo(s2);
                            }
                            if (c != 0) {
                                break;
                            }
                        }

                        // Final FINAL resort comparison - by original string length!  :-)
                        if (c == 0) {
                            String stripped1 = stripPrefixVs(v1);
                            String stripped2 = stripPrefixVs(v2);
                            c = Integer.valueOf(stripped1.length()).compareTo(stripped2.length());
                        }
                    }

                }
            } finally {
                if (DEBUG) {
                    String result = Arrays.toString(ver1) + " vs. " + Arrays.toString(ver2) + " C=" + c;
                    System.out.println("RESULT: [" + v1 + "] vs. [" + v2 + "] - " + result);
                }
            }
            return c;
        }
    };

    public final static SerializableComparator<File> COMPARE_FILES_BY_VERSION = new SerializableComparator<File>() {
        public int compare(File v1, File v2) {
            if (v1 == v2 || (v1 != null && v1.equals(v2))) {
                return 0;
            } else if (v1 == null) {
                return -1;
            } else if (v2 == null) {
                return 1;
            }

            String p1 = Strings.nullSafeTrim(v1.getParentFile());
            String p2 = Strings.nullSafeTrim(v2.getParentFile());
            int c = Strings.CASE_SENSITIVE_SANE.compare(p1, p2);
            if (c == 0) {
                c = COMPARE_VERSION_STRINGS.compare(v1.getName(), v2.getName());
            }
            return c;
        }
    };

    private static String stripPrefixVs(String s) {
        if (s.startsWith("V.") || s.startsWith("v.")) {
            return s.length() > 2 ? s.substring(2) : s;
        } else if (s.startsWith("V") || s.startsWith("v")) {
            return s.length() > 1 ? s.substring(1) : s;
        }
        return s;
    }

    public final static SerializableComparator<String> COMPARE_VERSION_STRINGS_TIEBREAK_ON_LENGTH = new SerializableComparator<String>() {
        public int compare(String v1, String v2) {
            int c = COMPARE_VERSION_STRINGS.compare(v1, v2);
            if (c == 0) {
                // penultimate last-resort comparison: length
                c = Integer.valueOf(v1.length()).compareTo(v2.length());
                if (c == 0) {
                    // last-resort comparison:  lexicographic (toString)
                    c = v1.compareTo(v2);
                }
            }
            return c;

        }
    };

    public static boolean isReleaseVersion(String s) {
        if (s == null || "".equals(s.trim())) {
            return false;
        }
        String[] split = split(s);
        int min = Integer.MAX_VALUE;
        for (int i = 0; i < split.length; i++) {
            final boolean isLastWord = (i == split.length - 1);
            String tok = split[i];
            String[] subSplit = splitIntoAlphasAndNums(tok);
            min = Math.min(min, minWordScore(subSplit, isLastWord));
        }
        return min >= 0;
    }

    /**
     * This logic sub-splits each component of the version number at any numeric-to-alpha transitions, as well at
     * any sequences of special characters.
     * Special case handling for alpha sequences that indicate "pre" or "post" releases, eg., this logic
     * knows that "alpha" versions comes before "beta" versions which comes before "rc" versions.
     *
     * @return comparator contract
     */
    private static int alphaNumericCompare(String s1, String s2, boolean isLastWord) {
        int c = 0;

        String[] words1 = splitIntoAlphasAndNums(s1);
        String[] words2 = splitIntoAlphasAndNums(s2);

        int min1 = minWordScore(words1, isLastWord);
        int min2 = minWordScore(words2, isLastWord);

        // System.out.println("[" + s1 + "] -> " + Arrays.toString(words1) + " vs. [" + s2 + "] -> " + Arrays.toString(words2));
        // System.out.println("min1=" + min1 + " min2=" + min2);

        // Special short-circuit if either "word" contains any of the
        // special pre-release words (e.g., "alpha", "beta", "rc", etc...).
        boolean isNegative1 = min1 < 0;
        boolean isNegative2 = min2 < 0;
        if (isNegative1 || isNegative2) {
            if (isNegative1 == isNegative2) {
                c = Integer.valueOf(min1).compareTo(min2);
                if (c != 0) {
                    return c;
                }
            } else {
                return isNegative1 ? -1 : 1;
            }
        }

        try {
            for (int j = 0; j < Math.min(words1.length, words2.length); j++) {
                final String sp1 = words1[j];
                final String sp2 = words2[j];

                // First look for special alpha sequences (e.g., "alpha" or "beta" or "rc"):
                int subScore1 = calculateScore(sp1, j == words1.length - 2);
                int subScore2 = calculateScore(sp2, j == words2.length - 2);
                c = subScore1 - subScore2;
                if (c != 0) {
                    return c;
                }

                // Since splitIntoAlphasAndNums() was called, that means that if 1st char is a digit, then
                // all characters are digits:
                if (startsWithDigit(sp1) || startsWithDigit(sp2)) {
                    Comparable<Long> v1 = toLong(sp1);
                    Long v2 = toLong(sp2);
                    if (v1 != null && v2 != null) {
                        c = v1.compareTo(v2);
                    } else {
                        // null == null, and null is smaller than non-null
                        c = v1 == v2 ? 0 : v1 == null ? -1 : 1;
                    }
                } else {
                    // Both are pure non-numerics, so use regular lexicographic compare:
                    if (subScore1 == 1 && subScore2 == 1) {
                        c = 0;
                    } else {
                        c = sp1.compareTo(sp2);
                    }
                }

                if (c != 0) {
                    return c;
                }
            }

            return c;

        } finally {
            if (DEBUG) {
                System.out.println("alphaNumericCompare(" + Arrays.toString(words1) + ", " + Arrays.toString(words2) + ") = " + c);
            }

        }


    }

    private final static boolean[] IS_DIGIT = new boolean['9' + 1];
    private final static boolean[] IS_SPECIAL = new boolean[128];

    static {
        IS_DIGIT['0'] = true;
        IS_DIGIT['1'] = true;
        IS_DIGIT['2'] = true;
        IS_DIGIT['3'] = true;
        IS_DIGIT['4'] = true;
        IS_DIGIT['5'] = true;
        IS_DIGIT['6'] = true;
        IS_DIGIT['7'] = true;
        IS_DIGIT['8'] = true;
        IS_DIGIT['9'] = true;
        IS_SPECIAL['`'] = true;
        IS_SPECIAL['^'] = true;
        IS_SPECIAL['~'] = true;
        IS_SPECIAL['='] = true;
        IS_SPECIAL['|'] = true;
        IS_SPECIAL['-'] = true;
        IS_SPECIAL[','] = true;
        IS_SPECIAL[';'] = true;
        IS_SPECIAL[':'] = true;
        IS_SPECIAL['!'] = true;
        IS_SPECIAL['?'] = true;
        IS_SPECIAL['/'] = true;
        IS_SPECIAL['\''] = true;
        IS_SPECIAL['"'] = true;
        IS_SPECIAL['('] = true;
        IS_SPECIAL[')'] = true;
        IS_SPECIAL['['] = true;
        IS_SPECIAL[']'] = true;
        IS_SPECIAL['<'] = true;
        IS_SPECIAL['>'] = true;
        IS_SPECIAL['{'] = true;
        IS_SPECIAL['}'] = true;
        IS_SPECIAL['@'] = true;
        IS_SPECIAL['$'] = true;
        IS_SPECIAL['*'] = true;
        IS_SPECIAL['\\'] = true;
        IS_SPECIAL['&'] = true;
        IS_SPECIAL['#'] = true;
        IS_SPECIAL['%'] = true;
        IS_SPECIAL['+'] = true;
        IS_SPECIAL['_'] = true;
        IS_SPECIAL['<'] = true;
        IS_SPECIAL['>'] = true;
        IS_SPECIAL[0] = true;
        IS_SPECIAL['\n'] = true;
        IS_SPECIAL['\r'] = true;
        IS_SPECIAL['\t'] = true;
        IS_SPECIAL[' '] = true;
    }

    /**
     * This method transforms the given String into an array of splits.  The splitting function splits on
     * transitions from alpha to numeric.  It also splits on any sequence of special characters, but
     * only includes alpha and numeric components of the string in its output.
     * <p>
     * It also always appends an empty-string to the returned split.
     * <p>
     * e.g.,  "abc123xyz" would return ["abc", "123", "xyz", ""]
     * "abc--12-3__;__xyz" would return ["abc", "12", "3", "xyz", ""]
     */
    static String[] splitIntoAlphasAndNums(String s) {
        if ("".equals(s)) {
            return new String[]{""};
        }
        s = s.toLowerCase(Locale.ENGLISH);

        List<String> splits = new ArrayList<String>();
        String tok = "";
        String prevTok = "";
        int prevPos = -1;

        char c = s.charAt(0);
        boolean isDigit = isDigit(c);
        boolean isSpecial = isSpecial(c);
        boolean isAlpha = !isDigit && !isSpecial;
        int prevMode = isAlpha ? 0 : isDigit ? 1 : -1;

        for (int i = 0; i < s.length(); i++) {
            c = s.charAt(i);
            isDigit = isDigit(c);
            isSpecial = isSpecial(c);
            isAlpha = !isDigit && !isSpecial;
            int mode = isAlpha ? 0 : isDigit ? 1 : -1;
            if (mode != prevMode) {
                if (!"".equals(tok)) {
                    if (isUnsplittable(prevTok)) {
                        splits.set(prevPos, prevTok + tok);
                    } else {
                        splits.add(tok);
                    }
                    prevTok = tok;
                    prevPos = splits.size() - 1;
                    tok = "";
                }
            }

            // alpha=0, digit=1.  Don't append for specials.
            if (mode >= 0) {
                // Special case for minus sign.
                if (i == 1 && isDigit && '-' == s.charAt(0)) {
                    tok = "-";
                }
                tok += c;
            }
            prevMode = mode;
        }
        if (!"".equals(tok)) {
            if (isUnsplittable(prevTok)) {
                splits.set(prevPos, prevTok + tok);
            } else {
                splits.add(tok);
            }
        }
        splits.add("");  // very important: append empty-string to all returned splits.
        return splits.toArray(new String[splits.size()]);
    }

    private static boolean isUnsplittable(String tok) {
        return "jdbc".equalsIgnoreCase(tok) || "jdk".equalsIgnoreCase(tok) || "jre".equalsIgnoreCase(tok);
    }

    public static String stripSpecialSuffix(String version) {
        int x = version.lastIndexOf('.');
        if (x >= 0) {
            String suffix = version.substring(x + 1).trim().toLowerCase(Locale.ENGLISH);
            if (suffix.length() > 1) {

                // If first part of suffix contains special word, strip final suffix.
                String[] split = splitIntoAlphasAndNums(suffix);
                int score = calculateScore(split[0], split.length == 2);
                if (score != 0 && score != 100 && score != 1000) {
                    return version.substring(0, x);
                }
            }
        }
        return version;
    }

    private static boolean startsWithPreReleaseWord(String word) {
        String[] words = splitIntoAlphasAndNums(word);
        if (words.length > 1) {
            return calculateScore(words[0], words.length == 2) < 0;
        }
        return false;
    }

    private static int minWordScore(String[] words, boolean isLastWord) {
        int min = Integer.MAX_VALUE;
        for (int i = 0; i < words.length; i++) {
            String word = words[i];
            boolean isLastOfLast = isLastWord && (i == words.length - 2);
            min = Math.min(min, calculateScore(word, isLastOfLast));
        }
        return min;
    }

    private static int calculateScore(String word, boolean isLastWord) {

        if (word == null) {
            return 0;
        }
        word = word.toLowerCase(Locale.ROOT);

        // special case for "RC" or "alpha" or "beta" or "a" or "b" or "u" or "update" or
        // "patch" or "p" or "rev" or "svn" or "bzr" or "rel" or "release" etc...

        if (word.equals("")) { // empty-string makes "2.3.5" equal "2.3.5.RELEASE".
            return 1;
        } else if (word.equals("final")) {
            return 1;
        } else if (word.equals("ga")) {
            return 1;
        } else if (word.equals("release")) {
            return 1;
        } else if (word.equals("update")) {
            return 1;
        } else if (word.equals("u") && !isLastWord) {
            return 1;
        } else if (word.equals("sp")) {
            return 1;
        } else if (word.equals("patch")) {
            return 1;
        } else if (word.equals("p") && !isLastWord) {
            return 1;
        } else if (word.equals("hotfix")) {
            return 1;
        } else if (word.startsWith("jdk")) {
            return 1;
        } else if (word.startsWith("jre")) {
            return 1;
        } else if (word.startsWith("jdbc")) {
            return 1;
        } else if (word.equals("android")) {
            return 1;
        } else if (word.equals("fix")) {
            return 1;
        } else if (word.equals("dev")) {
            return -90;
        } else if (word.equals("b") && !isLastWord) {
            return -93;
        } else if (word.equals("beta")) {
            return -96;
        } else if (word.equals("a") && !isLastWord) {
            return -99;
        } else if (word.equals("alpha")) {
            return -102;
        } else if (word.equals("snapshot")) {
            return -105;
        } else if (word.equals("ea")) {
            return -108;
        } else if (word.equals("eap")) {
            return -111;
        } else if (word.equals("early")) {
            return -114;
        } else if (word.equals("incubating")) {
            return -117;
        } else if (word.equals("pre")) {
            return -120;
        } else if (word.equals("prerelease")) {
            return -123;
        } else if (word.equals("preview")) {
            return -126;
        } else if (word.equals("build")) {
            return -129;
        } else if (word.equals("push0ver")) {
            return -132;
        } else if (word.equals("draft")) {
            return -135;
        } else if (word.equals("qa")) {
            return -138;
        } else if (word.equals("cvs")) {
            return -201;
        } else if (word.equals("svn")) {
            return -202;
        } else if (word.equals("bzr")) {
            return -203;
        } else if (word.equals("hg")) {
            return -204;
        } else if (word.equals("git")) {
            return -205;
        } else if (word.equals("rev")) {
            return -12;
        } else if (word.equals("cr")) {
            return -10;
        } else if (word.equals("rc")) {
            return -7;
        } else if (word.equals("m") && !isLastWord) {
            return -8;
        } else if (word.equals("milestone")) {
            return -9;
        }
        Long l = toLong(word);
        if (l != null) {
            // a pure number (with no alpha) wins against everything.
            // and negative pure numbers always score -1000
            return l >= 0 ? 1000 : -1000;
        } else {
            return 100;
        }
    }

    private static boolean isDigit(char c) {
        return c < IS_DIGIT.length && IS_DIGIT[c];
    }

    private static boolean isSpecial(char c) {
        return c < IS_SPECIAL.length && IS_SPECIAL[c];
    }

    private static boolean startsWithDigit(String s) {
        switch (s.length()) {
            case 0:
                return false;
            case 1:
                return isDigit(s.charAt(0));
            default:
                char c = s.charAt(0);
                return isDigit(c) || c == '-' && isDigit(s.charAt(1));
        }
    }

    private static Long toLong(String s) {
        if ("".equals(s)) {
            return null; // no digits.
        }
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException nfe) {
            return null; // contained alpha, or Number larger than Long.MAX_VALUE ?
        }
    }


    private static boolean anyIsNull(Object o1, Object o2) {
        return o1 == null || o2 == null;
    }

    private static int compareNulls(Object o1, Object o2) {
        if (o1 == null && o2 == null) {
            return 0;
        } else if (o1 == null) {
            return -1;
        } else {
            return 1;
        }
    }

    public static int compare(String s1, String s2) {
        return COMPARE_VERSION_STRINGS.compare(s1, s2);
    }
}

