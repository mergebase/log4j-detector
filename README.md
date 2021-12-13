# log4j-detector
Detects log4j versions on your file-system, including deeply recursively nested copies (jars inside jars inside jars).

# Example usage:
java -jar log4j-detector-2021.12.12.jar [path-to-scan] > hits.txt

![Terminal output from running java -jar log4j-detector.jar in a terminal](./log4j-detector.png)

# What are those "file1.war!/path/to/file2.zip!/path/to/file3.jar!/path/to/log4j.jar" results about?
The "!" means the log4j-detector entered a zip archive (e.g., *.zip, *.ear, *.war, *.aar, *.jar).  Since zip files can contain zip files, a single result might contain more than one "!" indicator in its result.

Note:  the log4j-detector only recursively enters zip archives.  It does not enter tar or gz or bz2, etc. The main reason being that Java systems are often configured to execute jars inside jars, but they are never configured to execute other file formats (that I know of!).  And so a log4j copy inside a *.tar.gz is probably not reachable for a running Java system, and hence, not a vulnerability worth reporting.

2nd note:  for zips-inside-zips our scanner does load the inner-zip completely into memory (using ByteArrayInputStream) before attempting to scan it.  You might need to give Java some extra memory if you have extremely large inner-zips on your system (e.g., 1 GB or larger).

# Build From Source:
```
git clone https://github.com/mergebase/log4j-detector.git
cd log4j-detector/
mvn install
java -jar target/log4j-detector-2021.12.12.jar
```

# License
GPL version 3.0

# How Does It Work?
The Java compiler stores String literals directly in the compiled *.class files.  If log4j-detector detects a file named "JndiManager.class"
on your file-system, it then examines that file for this String: "Invalid JNDI URI - {}".  Turns out that specific String literal
is only present in the patched version of Log4J (version 2.15.0).  Any versions of Log4J without that String are vulnerable.

# What About Log4J 1.2.x ?
Only versions of Log4J 2.x (from 2.0-beta9 to 2.14.1) are vulnerable to CVE-2021-44228.

# How Can I Be Sure This Isn't A Trojan Pretending To Be A Log4J Detector?
Great question! Since we include the complete source code here in Github (all 600 lines of Java), as well as the steps to build it, and since this tool has zero dependencies, it shouldn't take too long to carefully study the code to your satisfaction. If you don't trust Maven you can go directly into the "src/main/java/com/mergebase/log4j" directory and type "javac \*.java".  That works, too!

# What Is MergeBase All About?
[MergeBase](https://mergebase.com/) is an SCA company (Software Composition Analysis) based in Vancouver, Canada. We're similar to companies like Snyk, Sonatype, Blackduck, etc., in that we help companies detect and manage vulnerable open-source libraries in their software. Check us out! We have great accuracy, language support, and we're not too expensive, either: [mergebase.com/pricing](https://mergebase.com/pricing/)


