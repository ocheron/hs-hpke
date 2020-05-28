#!/bin/sh

DESTDIR="`dirname "$0"`"
FILENAME="$DESTDIR"/test-vectors.json
URL=https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json

curl -o "$FILENAME" "$URL" \
    && rm -f "$FILENAME".gz \
    && gzip -n --best "$FILENAME"
