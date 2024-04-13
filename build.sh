#!/bin/sh

PATH_ROOT=.
PATH_SRC=$PATH_ROOT/src
PATH_BIN=$PATH_ROOT/bin
PATH_INT=$PATH_BIN/int
FILE_JAR=$PATH_BIN/encrypt.jar
FILE_MANIFEST=$PATH_SRC/Manifest.mf

# This is a horribly inflexible build solution, but I'm a noob to real-world
# Java development and the existing solutions are either 20 years obsolete or
# are way overkill for this simple program.
javac $PATH_SRC/*.java -d $PATH_INT
jar cvfm $FILE_JAR $FILE_MANIFEST $PATH_INT/*

