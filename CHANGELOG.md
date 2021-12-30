
## To Build Or Download Previous Versions

Please see the tags page: https://github.com/mergebase/log4j-detector/tags

## v2021.12.29

- Ability to detect log4j-core-2.3.2.jar, log4j-core-2.12.4.jar, and log4j-core-2.17.1.jar (all are \_SAFE\_).

## v2021.12.22

- Ability to detect log4j-core-2.3.1.jar and log4j-core-2.12.3.jar (both are \_SAFE\_).
- Improved ability to deal with shaded jars.

## v2021.12.20

- Added support for --stdin, --json, and --exclude options.
- Added support for scanning *.jpi and *.hpi files (essentially zip files).

## v2021.12.17

- Ability to detect log4j-core-2.17.0.jar 

## v2021.12.16

- Properly detect exploded Log4J versions (that are not inside *.jar and instead are just sitting as *.class directly on disk).

- Fixed problem that was causing some inner-jar entries to be misread. ("Unexpected end of ZLIB stream").

- All problems now printed on STDERR instead of STDOUT.

- Only check read-permission on files we're interested in (makes for a lot fewer "cannot read!" errors).



