#!/bin/sh
echo 'This compiles and minifies css and javascript. initdb.sql has to be run manually in your database.' 
echo 'Compiling JS...'
cd js
sh compile.sh
echo 'Compiling CSS...'
cd ../scss
sh compile.sh
echo 'Done.'
