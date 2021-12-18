/*
 *  Copyright (C) 2021, MergeBase Software Incorporated ("MergeBase")
 *  of Coquitlam, BC, Canada - https://mergebase.com/
 *
 *  MergeBase licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.mergebase.log4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility for converting back and forth between Java objects (Map, Collection, String, Number, Boolean, null) and JSON.
 */
public class Java2Json {

    public static final boolean tolerant = false;

    private int pos;
    private char[] json;

    private Java2Json(int pos, char[] json) {
        this.pos = pos;
        this.json = json;
    }

    private final static Long ZERO = Long.valueOf("0");
    private final static int MAP = 0;
    private final static int LIST = 1;
    private final static int STRING = 2;
    private final static int NUMBER = 3;
    private final static int BOOLEAN = 5;
    private final static int NULL = 6;
    private final static int MODE_WHITESPACE = -1;
    private final static int MODE_NORMAL = 0;
    private final static int MODE_BACKSLASH = 1;

    public static String makePretty(String ugly) {
        Object juliusJson = parse(ugly);
        return format(true, juliusJson);
    }

    public static Map<String, Object> parseToMap(String json) {
        if (json == null) {
            return null;
        }
        json = json.trim();
        if ("".equals(json)) {
            return new LinkedHashMap<String, Object>();
        } else {
            return (Map) parse(json);
        }
    }

    public static List parseToList(String json) {
        if (json == null) {
            return null;
        }
        json = json.trim();
        if ("".equals(json)) {
            return new ArrayList();
        } else {
            return (List) parse(json);
        }
    }

    /**
     * Converts a String of JSON into a Java representation,
     * parsing the result into a structure of nested
     * Map, List, Boolean, Long, Double, String and null objects.
     *
     * @param json String to parse
     * @return A Java representation of the parsed JSON String
     * based on java.util.Map, java.util.List, java.lang.Boolean,
     * java.lang.Number, java.lang.String and null.
     */
    public static Object parse(String json) {
        char[] c = json.toCharArray();
        Java2Json p = new Java2Json(0, c);

        try {
            int type = nextObject(p);
            Object o = parseObject(type, p);
            finalWhitespace(p);
            return o;

        } catch (RuntimeException re) {
            int charsLeft = c.length - p.pos;
            if (p.pos > 10) {
                // System.out.println("NEAR: [" + new String(c, p.pos - 10, Math.min(10 + charsLeft, 20)));
            } else {
                // System.out.println("NEAR: [" + new String(c, 0, Math.min(10 + charsLeft, Math.min(20, c.length))));
            }
            throw re;
        }
    }

    public static String format(Object o) {
        return format(false, o);
    }

    /**
     * Formats a Java object into a JSON String.
     * <p>
     * Expects the Java object to be a java.util.Map, java.util.Iterable,
     * java.lang.String, java.lang.Number, java.lang.Boolean, or null, or
     * nested structure of the above.  All other object types cause a
     * RuntimeException to be thrown.
     *
     * @param o Java object to convert into a JSON String.
     * @return a valid JSON String
     */
    public static String format(boolean pretty, Object o) {
        StringBuilder buf = new StringBuilder(1024);
        prettyPrint(pretty, o, 0, buf);
        String s = buf.toString();
        if (o instanceof Map) {
            return "{" + s + "}";
        } else if (o instanceof Iterable || o instanceof Object[]) {
            return "[" + s + "]";
        } else {
            return s;
        }
    }

    public static String parseJsonString(String s) {
        s = s.trim();
        if (!s.startsWith("\"")) {
            s = '"' + s + '"';
        }
        char[] c = s.toCharArray();
        Java2Json p = new Java2Json(0, c);
        return (String) parseObject(STRING, p);
    }

    private static Object parseObject(int type, Java2Json p) {
        switch (type) {
            case MAP:
                Map m = new LinkedHashMap();
                while (hasNextItem(p, '}')) {
                    String key = nextString(p);
                    nextChar(p, ':');
                    type = nextObject(p);
                    Object obj = parseObject(type, p);
                    /*
                    if (m.containsKey(key)) {
                        throw new RuntimeException("JSON Map Already Contains Key [" + key + "]");
                    }
                     */
                    m.put(key, obj);
                }
                return m;

            case LIST:
                ArrayList l = new ArrayList();
                while (hasNextItem(p, ']')) {
                    type = nextObject(p);
                    Object obj = parseObject(type, p);
                    l.add(obj);
                }
                return l;

            case STRING:
                return nextString(p);

            case NUMBER:
                return nextNumber(p);

            case BOOLEAN:
                return nextBoolean(p);

            case NULL:
                return nextNull(p);

            default:
                throw new RuntimeException("invalid type: " + type);
        }
    }

    private static boolean hasNextItem(Java2Json p, char closingBracket) {
        char prev = p.json[p.pos - 1];
        boolean isMap = closingBracket == '}';

        boolean nextCommaExists = nextChar(p, ',', false);
        if (!nextCommaExists) {
            p.pos--;
        }

        char c = p.json[p.pos];
        if (c == closingBracket) {
            p.pos++;
            return false;
        } else if (nextCommaExists) {
            return true;
        } else {
            if (isMap && prev == '{') {
                return true;
            } else if (!isMap && prev == '[') {
                return true;
            }
            throw new RuntimeException("expected whitespace or comma or " + closingBracket + " but found: " + c);
        }
    }

    private static int nextObject(Java2Json p) {
        for (int i = p.pos; i < p.json.length; i++) {
            p.pos++;
            char c = p.json[i];

            if (!isWhitespace(c)) {
                if (c == '"') {
                    p.pos--;
                    return STRING;
                } else if (c == '{') {
                    return MAP;
                } else if (c == '[') {
                    return LIST;
                } else if (c == '-' || (c >= '0' && c <= '9')) {
                    p.pos--;
                    return NUMBER;
                } else if (c == 'n') {
                    p.pos--;
                    return NULL;
                } else if (c == 't' || c == 'f') {
                    p.pos--;
                    return BOOLEAN;
                } else {
                    throw new RuntimeException("Expected whitespace or JSON literal, but got: " + c);
                }
            }
        }
        return -1; // there is no next object, so we're done
    }

    private static void finalWhitespace(Java2Json p) {
        for (int i = p.pos; i < p.json.length; i++) {
            p.pos++;
            char c = p.json[i];
            if (!isWhitespace(c)) {
                throw new RuntimeException("Expected whitespace or EOF but got: " + c);
            }
        }
        return;
    }

    private static boolean nextChar(Java2Json p, char charToFind) {
        return nextChar(p, charToFind, true);
    }

    private static boolean nextChar(Java2Json p, char charToFind, boolean doThrow) {
        for (int i = p.pos; i < p.json.length; i++) {
            p.pos++;
            char c = p.json[i];

            if (!isWhitespace(c)) {
                if (c == charToFind) {
                    return true;
                } else {
                    if (doThrow) {
                        throw new RuntimeException("Expected whitespace or " + charToFind + " but got: " + c);
                    } else {
                        return false;
                    }
                }
            }
        }
        int offset = Math.max(0, p.pos - 10);
        int count = p.pos - offset;
        throw new RuntimeException("Never found " + charToFind + " context=" + new String(p.json, offset, count));
    }

    private static Object nextNull(Java2Json p) {
        char c = p.json[p.pos++];
        try {
            if (c == 'n') {
                c = p.json[p.pos++];
                if (c == 'u') {
                    c = p.json[p.pos++];
                    if (c == 'l') {
                        c = p.json[p.pos++];
                        if (c == 'l') {
                            return null;
                        }
                    }
                }
            }
        } catch (ArrayIndexOutOfBoundsException aioobe) {
            throw new RuntimeException("expected null literal but ran of out string to parse");
        }
        throw new RuntimeException("expected null literal but ran into bad character: " + c);
    }

    private static Boolean nextBoolean(Java2Json p) {
        char c = p.json[p.pos++];
        try {
            if (c == 't') {
                c = p.json[p.pos++];
                if (c == 'r') {
                    c = p.json[p.pos++];
                    if (c == 'u') {
                        c = p.json[p.pos++];
                        if (c == 'e') {
                            return Boolean.TRUE;
                        }
                    }
                }
            } else if (c == 'f') {
                c = p.json[p.pos++];
                if (c == 'a') {
                    c = p.json[p.pos++];
                    if (c == 'l') {
                        c = p.json[p.pos++];
                        if (c == 's') {
                            c = p.json[p.pos++];
                            if (c == 'e') {
                                return Boolean.FALSE;
                            }
                        }
                    }
                }
            }
        } catch (ArrayIndexOutOfBoundsException aioobe) {
            throw new RuntimeException("expected true/false literal but ran of out string to parse");
        }
        throw new RuntimeException("expected true/false literal but ran into bad character: " + c);
    }

    private static Number nextNumber(Java2Json p) {
        StringBuilder buf = new StringBuilder();
        for (int i = p.pos; i < p.json.length; i++) {
            p.pos++;
            char c = p.json[i];
            if (isWhitespace(c) || c == ',' || c == '}' || c == ']') {
                p.pos--;
                break;
            } else if (c == '-' || c == '+' || c == 'e' || c == 'E' || c == '.' || (c >= '0' && c <= '9')) {
                buf.append(c);
            } else {
                throw new RuntimeException("expected number but got: " + c);
            }
        }

        String s = buf.toString();
        char char0 = s.length() > 0 ? s.charAt(0) : '_';
        if (char0 == '+') {
            throw new RuntimeException("number literal cannot start with plus: " + s);
        } else if ("-".equals(s)) {
            throw new RuntimeException("number literal cannot be negative sign by itself");
        }
        boolean isNegative = char0 == '-';

        if (isNegative) {
            s = s.substring(1);
        }

        if ("0".equals(s)) {
            return ZERO;
        }

        if (s.startsWith(".")) {
            throw new RuntimeException("number literal cannot start with decimal point: " + s);
        }
        if (!s.startsWith("0.") && !s.startsWith("0e") && !s.startsWith("0E")) {
            if (s.startsWith("0")) {
                throw new RuntimeException("number literal cannot have leading zero: " + s);
            }
        }

        if (contains(s, ".e") || contains(s, ".E")) {
            throw new RuntimeException("number literal invalid exponential: " + s);
        }

        if (s.endsWith("e") || s.endsWith("E") || s.endsWith("+") || s.endsWith("-") || s.endsWith(".")) {
            throw new RuntimeException("number literal cannot end with [eE+-.] " + s);
        }

        int[] charCounts = charCounts(s);
        int periods = charCounts[0];
        int minuses = charCounts[1];
        int plusses = charCounts[2];
        int eTotal = charCounts[3];
        int plussesAndMinuses = plusses + minuses;

        if (plussesAndMinuses > 0) {
            if (plussesAndMinuses > 1) {
                throw new RuntimeException("invalid number literal - too many plusses/minuses: " + s);
            } else {
                boolean isValidPlus = false;
                boolean isValidMinus = minuses > 0 && (contains(s, "e-") || contains(s, "E-"));
                if (!isValidMinus) {
                    isValidPlus = plusses > 0 && (contains(s, "e+") || contains(s, "E+"));
                }
                if (!isValidPlus && !isValidMinus) {
                    throw new RuntimeException("invalid number literal: " + s);
                }
            }
        }

        if (periods > 1 || eTotal > 1) {
            throw new RuntimeException("invalid number literal: " + s);
        }

        if (isNegative) {
            s = "-" + s;
        }
        if (periods == 1 || eTotal == 1) {
            return new Double(s);
        } else {
            try {
                return new Long(s);
            } catch (NumberFormatException nfe) {
                return new Double(s);
            }
        }
    }


    private static int[] charCounts(String s) {

        // periods, dashes, plusses, lowerOrUpperEs
        int[] counts = {0, 0, 0, 0};

        for (int i = 0; i < s.length(); i++) {
            switch (s.charAt(i)) {
                case '.':
                    counts[0]++;
                    break;
                case '-':
                    counts[1]++;
                    break;
                case '+':
                    counts[2]++;
                    break;
                case 'E':
                case 'e':
                    counts[3]++;
                    break;
                default:
                    break;
            }
        }
        return counts;
    }

    private static String nextString(Java2Json p) {
        int mode = MODE_WHITESPACE;
        StringBuilder buf = new StringBuilder();
        for (int i = p.pos; i < p.json.length; i++) {
            p.pos++;
            char c = p.json[i];
            switch (mode) {
                case MODE_WHITESPACE:
                    if (c == '"') {
                        mode = MODE_NORMAL;
                    } else if (!isWhitespace(c)) {
                        throw new RuntimeException("json expecting double-quote: " + c);
                    }
                    break;
                case MODE_NORMAL:
                    if (c == '\\') {
                        mode = MODE_BACKSLASH;
                    } else if (c == '"') {
                        return buf.toString();
                    } else {
                        if (Character.isISOControl(c)) {
                            StringBuilder hex = new StringBuilder(Integer.toHexString(c));
                            if ("7f".equalsIgnoreCase(hex.toString())) {
                                buf.append(c);
                            } else {
                                for (int j = hex.length(); j < 4; j++) {
                                    hex.insert(0, "0");
                                }

                                if (!tolerant) {
                                    throw new RuntimeException("control characters in string literal must be escaped: \\u" + hex);
                                } else {
                                    buf.append("\\u").append(hex);
                                }
                            }
                        } else if (c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') {
                            throw new RuntimeException("json string literal invalid character: " + c);
                        } else {
                            buf.append(c);
                        }
                    }
                    break;
                case MODE_BACKSLASH:
                    switch (c) {
                        case '/':
                            buf.append('/');
                            break;
                        case 'b':
                            buf.append('\b');
                            break;
                        case 'f':
                            buf.append('\f');
                            break;
                        case 'n':
                            buf.append('\n');
                            break;
                        case 'r':
                            buf.append('\r');
                            break;
                        case 't':
                            buf.append('\t');
                            break;
                        case '"':
                            buf.append('"');
                            break;
                        case '\\':
                            buf.append('\\');
                            break;
                        case 'u':
                            StringBuilder hex = new StringBuilder();
                            for (int j = 0; j < 4; j++) {
                                try {
                                    char hexChar = p.json[p.pos++];
                                    if (isHex(hexChar)) {
                                        hex.append(hexChar);
                                    } else {
                                        throw new RuntimeException("invalid \\u encoded character (must be hex): " + hexChar);
                                    }
                                } catch (ArrayIndexOutOfBoundsException aioobe) {
                                    throw new RuntimeException("\\u encoded literal ran out of string to parse");
                                }
                            }
                            buf.append((char) Integer.parseInt(hex.toString(), 16));
                            i += 4;
                            break;
                        default:
                            throw new RuntimeException("invalid backslash protected character: " + c);
                    }
                    mode = MODE_NORMAL;
                    break;
            }
        }
        throw new RuntimeException("never found literal string terminator \"");
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private static boolean contains(String string, String thing) {
        return string.indexOf(thing) >= 0;
    }

    private static StringBuilder prettyPrint(
            final boolean pretty, final Object objParam, final int level, final StringBuilder buf
    ) {
        Iterator it;
        final Object obj;
        if (objParam instanceof Object[]) {
            Object[] objs = (Object[]) objParam;
            obj = Arrays.asList(objs);
        } else {
            obj = objParam;
        }

        if (obj instanceof Map) {
            Map m = (Map) obj;
            it = m.entrySet().iterator();
        } else if (obj instanceof Iterable) {
            Iterable l = (Iterable) obj;
            it = l.iterator();
        } else {
            it = Collections.singleton(obj).iterator();
        }

        while (it.hasNext()) {
            Object o = it.next();
            Object val = o;
            if (val instanceof Object[]) {
                Object[] objs = (Object[]) val;
                val = Arrays.asList(objs);
            }

            if (pretty) {
                buf.append('\n');
                indent(buf, level);
            }
            if (o instanceof Map.Entry) {
                Map.Entry me = (Map.Entry) o;
                Object keyObj = me.getKey();
                String key;
                if (keyObj instanceof String) {
                    key = (String) keyObj;
                } else {
                    key = String.valueOf(keyObj);
                }
                buf.append('"');
                jsonSafe(key, buf);
                buf.append('"').append(':');
                val = me.getValue();
                if (val instanceof Object[]) {
                    Object[] objs = (Object[]) val;
                    val = Arrays.asList(objs);
                }
            }

            if (val == null || val instanceof Boolean || val instanceof Number) {
                jsonSafe(val, buf);
            } else if (val instanceof Iterable) {
                buf.append('[');
                int lenBefore = buf.length();
                prettyPrint(pretty, val, level + 1, buf);
                if (pretty) {
                    int lenAfter = buf.length();
                    if (lenBefore < lenAfter) {
                        buf.append('\n');
                        indent(buf, level);
                    }
                }
                buf.append(']');
            } else if (val instanceof Map) {
                buf.append('{');
                int lenBefore = buf.length();
                prettyPrint(pretty, val, level + 1, buf);
                if (pretty) {
                    int lenAfter = buf.length();
                    if (lenBefore < lenAfter) {
                        buf.append('\n');
                        indent(buf, level);
                    }
                }
                buf.append('}');
            } else {
                buf.append('"');
                jsonSafe(val, buf);
                buf.append('"');
            }
            if (it.hasNext()) {
                buf.append(',');
            }
        }
        return buf;
    }

    private static StringBuilder indent(StringBuilder buf, int level) {
        for (int i = 0; i < level; i++) {
            buf.append("  ");
        }
        return buf;
    }

    private static void jsonSafe(Object o, StringBuilder buf) {
        final String s;
        if (o == null) {
            buf.append("null");
            return;
        } else if (o instanceof Boolean || o instanceof Number) {
            String val = o.toString();
            if ("Infinity".equals(val)) {
                val = "1e99999";
            } else if ("-Infinity".equals(val)) {
                val = "-1e99999";
            }
            buf.append(val);
            return;
        } else if (o instanceof Map || o instanceof Iterable) {
            throw new RuntimeException("cannot make Map or Iterable into json string literal: " + o);
        } else if (o instanceof String) {
            s = (String) o;
        } else {
            s = String.valueOf(o);
        }

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\b':
                    buf.append("\\b");
                    break;
                case '\f':
                    buf.append("\\f");
                    break;
                case '\n':
                    buf.append("\\n");
                    break;
                case '\r':
                    buf.append("\\r");
                    break;
                case '\t':
                    buf.append("\\t");
                    break;
                case '\\':
                    buf.append("\\\\");
                    break;
                case '"':
                    buf.append("\\\"");
                    break;
                default:
                    // We're not interested in control characters U+0000 to U+001F aside from
                    // the allowed ones above.
                    if (Character.isISOControl(c)) {
                        String hex = Integer.toHexString(c);
                        buf.append("\\u");
                        for (int j = hex.length(); j < 4; j++) {
                            buf.append('0');
                        }
                        buf.append(hex);
                    } else {
                        buf.append(c);
                    }
                    break;
            }
        }
    }
}