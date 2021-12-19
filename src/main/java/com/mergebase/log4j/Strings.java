package com.mergebase.log4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class Strings {

    public final static String WHITESPACE_SEPARATOR = "[ \\t\\n\\x0B\\f\\r]+";
    public final static String WHITESPACE_COMMA_SEPARATOR = "[, \\t\\n\\x0B\\f\\r]+";
    public final static String WHITESPACE_COMMA_SEMICOLON_SEPARATOR = "[ \\t\\n\\x0B\\f\\r,;\\|]+";
    public final static String WHITESPACE_COMMA_SEPARATOR_BUT_NOT_SPACES = "[\\t\\n\\x0B\\f\\r,\\|]+";


    public static String nullSafeTrim(String s) {
        return s != null ? s.trim() : null;
    }

    /**
     * Given a line like "BLAH BLAH (column, foo, bar) BLAH BLAH"
     * returns a map:  {"column" --> 0, "foo" --> 1, "bar" --> 2}
     */
    public static Map<String, Integer> positions(String headerLine) {
        HashMap<String, Integer> m = new HashMap<String, Integer>();
        int j = headerLine.indexOf('(');
        int k = headerLine.indexOf(')');
        if (j >= 0 && j < k) {
            headerLine = headerLine.substring(j + 1, k);
            String[] toks = headerLine.split(Strings.WHITESPACE_COMMA_SEPARATOR);
            for (int i = 0; i < toks.length; i++) {
                m.put(toks[i], i);
            }
        } else {
            throw new RuntimeException("cannot parse headerLine for column positions: [" + headerLine + "]");
        }
        return m;
    }

    public static String nullSafeTrim(Object o) {
        if (o == null) {
            return "";
        } else if (o instanceof String) {
            return ((String) o).trim();
        } else {
            return o.toString().trim();
        }
    }

    /**
     * Default Java case-sensitive goes A-Za-z, but I prefer AaBbCc.
     */
    public final static Comparator<String> CASE_SENSITIVE_SANE = new Comparator<String>() {
        @Override
        public int compare(String s1, String s2) {
            if (s1 == s2) {
                return 0;
            } else if (s1 == null) {
                return -1;
            } else if (s2 == null) {
                return 1;
            }
            int c = s1.compareToIgnoreCase(s2);
            if (c == 0) {
                c = s1.compareTo(s2);
            }
            return c;
        }
    };

    public static Long parseLong(String s, long defaultVal) {
        s = s != null ? s.trim() : "";
        if ("".equals(s)) {
            return defaultVal;
        }
        try {
            return Long.parseLong(s);
        } catch (RuntimeException e) {
            return defaultVal;
        }
    }

    public static int countChar(String s, char c) {
        int count = 0;
        for (char ch : s.toCharArray()) {
            if (ch == c) {
                count++;
            }
        }
        return count;
    }

    public static int countLeadingChars(String s) {
        int count = 0;
        if (s.length() > 0) {
            char c = s.charAt(0);
            count = 1;
            for (int i = 1; i < s.length(); i++) {
                if (c == s.charAt(i)) {
                    count++;
                } else {
                    break;
                }
            }
        }
        return count;
    }


    /**
     * Strips leading characters from supplied string.
     * Also adds leading characters if necessary to create a string
     * that is at least minLen long.
     *
     * @param s      String to strip leading characters from.
     * @param minLen minimum length of String to return (padded with leading characters if necessary)
     * @return String with leading characters removed.
     */
    public static String stripLeadingCharacter(String s, char c, int minLen) {
        if (s == null) {
            return null;
        }
        StringBuilder result = null;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) != c) {
                result = new StringBuilder(s.substring(i));
                break;
            }
        }
        if (result == null) {
            result = new StringBuilder();
        }
        for (int i = result.length(); i < minLen; i++) {
            result.insert(0, c);
        }
        return result.toString();
    }

    public static String stripLeadingZeroes(long l, int minLen) {
        return stripLeadingCharacter(Long.toString(l), '0', minLen);
    }

    /**
     * Strips leading zeroes from supplied string.
     * Also adds leading zeroes if necessary to create a string
     * that is at least minLen long.
     *
     * @param s      String to strip leading zeroes from.
     * @param minLen minimum length of String to return (padded with leading zeroes if necessary)
     * @return String with leading zeroes removed.
     */
    public static String stripLeadingZeroes(String s, int minLen) {
        return stripLeadingCharacter(s, '0', minLen);
    }

    public static String stripTrailingNonAlphaNumerics(String s) {
        if (s == null) {
            return null;
        } else {
            StringBuilder buf = new StringBuilder(s);
            for (int i = s.length() - 1; i >= 0; i--) {
                char c = s.charAt(i);
                if (isLetterOrDigit(c)) {
                    return buf.toString();
                } else {
                    buf.deleteCharAt(i);
                }
            }
        }
        return "";
    }

    public static boolean isLetterOrDigit(char c) {
        return isLetter(c) || isDigit(c);
    }

    public static boolean isDigit(char c) {
        return '0' <= c && c <= '9';
    }

    public static boolean isLetter(char c) {
        return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z');
    }

    public static boolean containsOnlyDigits(String s) {
        if (s == null || "".equals(s)) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean isValid = (i == 0 && c == '-') || isDigit(c);
            if (!isValid) {
                return false;
            }
        }
        return true;
    }

    public static boolean containsOnlyLetters(String s) {
        if (s == null || "".equals(s)) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!isLetter(c)) {
                return false;
            }
        }
        return true;
    }

    public static List<String> intoLines(final String... strings) {
        List<String> list = new ArrayList<String>();
        if (strings != null) {
            for (final String s : strings) {
                if (s != null) {
                    StringReader sr = new StringReader(s);
                    BufferedReader br = new BufferedReader(sr);
                    String line;
                    try {
                        while ((line = br.readLine()) != null) {
                            list.add(line);
                        }
                    } catch (IOException ioe) {
                        throw new RuntimeException("impossible - StringReader does not throw IOException - " + ioe, ioe);
                    }
                }
            }
        }
        return list;
    }

    public static String cleanForSql(String s) {
        return cleanForSql(s, false);
    }

    public static String cleanForSql(String s, boolean doubleUpSingleQuotes) {
        s = s != null ? s.trim() : "";
        s = s.replace("\n", " ");
        s = s.replace("\r", " ");
        s = s.replace("\t", " ");
        if (doubleUpSingleQuotes) {
            return s.replace("'", "''");
        } else {
            return s.replace("'", "");
        }
    }

    public static boolean isYes(String s) {
        s = s != null ? s.trim().toLowerCase(Locale.ENGLISH) : "";
        return "1".equals(s) || "y".equals(s) || "t".equals(s) || "yes".equals(s) || "true".equals(s);
    }

    public static boolean isNo(String s) {
        s = s != null ? s.trim().toLowerCase(Locale.ENGLISH) : "";
        return "0".equals(s) || "n".equals(s) || "f".equals(s) || "no".equals(s) || "false".equals(s);
    }

    public static String safeForHTML(String s) {
        if (s == null) {
            return null;
        }
        s = s.replace("&", "&amp;");
        s = s.replace("\"", "&quot;");
        s = s.replace("<", "&lt;");
        s = s.replace(">", "&gt;");
        return s;
    }

    public static boolean startsWithYearDot(String s) {
        if (s != null && s.length() > 4 && (s.startsWith("20") || s.startsWith("19"))) {
            s = s.substring(2);
            if (s.charAt(2) == '.') {
                return Strings.isDigit(s.charAt(0)) && Strings.isDigit(s.charAt(1));
            }
        }
        return false;
    }

}
