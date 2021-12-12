# log4j-detector
Detects log4j versions on your file-system, including deeply recursively nested copies (jars inside jars inside jars).

# Example usage:
java -jar log4j-detector-2021.12.12.jar [path-to-scan] > hits.txt

![Terminal output from running java -jar log4j-detector.jar in a terminal](./log4j-detector.png)

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
