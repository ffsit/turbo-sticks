#!/bin/sh
files=`ls *.js`
for f in $files
do
	uglifyjs -c -m --ie8 --warn $f > ../../static/$f
done
