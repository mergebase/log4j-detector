# log4j-detector
Detects log4j versions on your file-system, including deeply recursively nested copies (jars inside jars inside jars).

# Example usage:
java -jar log4j-detector-2021.12.12.jar [path-to-scan] > hits.txt

![Terminal output from running java -jar log4j-detector.jar in a terminal](./log4j-detector.png)

# What are those "file1.war!/path/to/file2.zip!/path/to/file3.jar!/path/to/log4j.jar" results about?
The "!" means the log4j-detector entered a zip archive (e.g., *.zip, *.ear, *.war, *.aar, *.jar).  Since zip files can contain zip files, a single result might contain more than one "!" indicator in its result.

Note:  the log4j-detector only recursively enters zip archives.  It does not enter tar or gz or bz2, etc. The main reason being that Java systems are often configured to execute jars inside jars, but they are never configured to execute other file formats (that I know of!).  And so a log4j copy inside a *.tar.gz is probably not reachable for a running Java system, and hence, not a vulnerability worth reporting.

2nd note:  for zips-inside-zips our scanner does load the inner-zip completely into memory (using ByteArrayInputStream) before attempting to scan it.  You might need to give Java some extra memory if you have extremely large inner-zips on your system (e.g., 1 GB or larger).

# Build from source:
mvn install

# License
GPL version 3.0

# How Does It Work?
The Java compiler stores String literals directly in the compiled *.class files.  If log4j-detector detects a file named "JndiManager.class"
on your file-system, it then examines that file for this String: "Invalid JNDI URI - {}".  Turns out that specific String literal
is only present in the patched version of Log4J (version 2.15.0).  Any versions of Log4J without that String are vulnerable.

# What About Log4J 1.2.x ?
Only versions of Log4J 2.x (from 2.0-beta9 to 2.14.1) are vulnerable to CVE-2021-44228.
