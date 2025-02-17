#!/bin/sh
if [ $# -ne 2 ]
then
    echo "expected 2 parameters, but got $#: $*"
    exit 1
elif [ ! -d "$1" ]; then
    echo "expected first parameter to be a directory, but got: $*"
    exit 1
fi

FILESDIR=$1
SEARCHSTR=$2

filepaths=$(find "$FILESDIR" -type f)

count_files(){
    echo "$filepaths" | wc -l
}

count_lines() {
    echo "$filepaths" |xargs cat|grep -c "$SEARCHSTR"
}


echo "The number of files are $(count_files) and the number of matching lines are $(count_lines)"