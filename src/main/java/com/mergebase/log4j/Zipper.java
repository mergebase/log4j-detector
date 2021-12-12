package com.mergebase.log4j;

import java.util.jar.JarInputStream;


/**
 * An interface that allows us to re-read a ZipInputStream as many times as we want.
 */
public interface Zipper {
    JarInputStream getFreshZipStream();

    void close();
}

