#!/bin/sh
files=`ls *.js`
for f in $files
do
	/usr/local/www/turbo-sticks/node_modules/uglify-js/bin/uglifyjs -c -m --ie8 --warn $f > ../../static/$f
done
