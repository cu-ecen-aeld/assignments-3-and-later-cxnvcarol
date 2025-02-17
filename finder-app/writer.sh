#!/bin/sh
writefile=$1
writestr=$2

if [ $# -ne 2 ]
then
    echo "expected 2 parameters, but got $#: $*"
    exit 1
fi

write_my_file(){
    mkdir -p "$(dirname "$writefile")"
    echo "$writestr" > "$writefile"
}

if ! write_my_file; then
    echo "Oops! Something unexpected happen"
    exit 1
fi