package com.mergebase.log4j;

public class Throwables {

    public static void rethrowIfUnchecked(Throwable t) {
        if (t instanceof Error) {
            throw (Error) t;
        } else if (t instanceof RuntimeException) {
            throw (RuntimeException) t;
        }
    }

}
