#!/bin/sh
# Build a shareable extension zip (only the files Chrome needs - no backend/dev files).
set -e
NAME="cyberuzcheck-extension"
OUT="dist"

rm -rf "$OUT/$NAME" "$OUT/$NAME.zip"
mkdir -p "$OUT/$NAME"

cp manifest.json \
   background.js content.js popup.js blocked.js \
   popup.html blocked.html popup.css \
   icon16.png icon48.png icon128.png \
   "$OUT/$NAME/"

( cd "$OUT/$NAME" && zip -qr "../$NAME.zip" . )
echo "built $OUT/$NAME.zip"
echo "  - unzip and 'Load unpacked' the folder, or"
echo "  - upload $OUT/$NAME.zip to the Chrome Web Store dev console"
