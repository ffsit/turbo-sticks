#!/bin/sh
sassc -t compressed style.scss style.css
sassc -t compressed stream.scss ../../static/stream.css
sassc -t compressed chat.scss ../../static/chat.css
css-purge -f config.json
