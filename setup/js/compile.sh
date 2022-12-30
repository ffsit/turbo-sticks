#!/bin/sh
files=`ls *.js`
for f in $files
do
	uglifyjs "${f}" -c -m --ie8 --warn -o "../../static/${f}"
done
