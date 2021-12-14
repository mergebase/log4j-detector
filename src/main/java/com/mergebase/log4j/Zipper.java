package com.mergebase.log4j;

import java.util.zip.ZipInputStream;


/**
 * An interface that allows us to re-read a ZipInputStream as many times as we want.
 */
public interface Zipper {
    ZipInputStream getFreshZipStream();

    void close();
}

