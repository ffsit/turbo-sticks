#!/bin/sh
sassc -t compressed style.scss style.css
sassc -t compressed stream.scss ../../static/stream.css
css-purge -f config.json
