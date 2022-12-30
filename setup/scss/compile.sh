#!/bin/sh
mkdir -p build
files=$(ls *.scss | grep -v '^_')
for f in $files
do
	fname=$(basename $f .scss)
	sassc -t compressed "${f}" "build/${fname}.css"
	css-purge -f config.json -i "build/${fname}.css" -o "../../static/${fname}.css"
done
