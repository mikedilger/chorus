#!/bin/bash

if ! command -v curl 2>&1 >/dev/null
then
    echo "curl command is required."
    exit 1
fi

if ! command -v jq 2>&1 >/dev/null
then
    echo "jq command is required."
    exit 1
fi

if ! command -v nak 2>&1 >/dev/null
then
    echo "nak command is required. https://github.com/fiatjaf/nak"
    exit 1
fi

# UPLOAD TEST ------------

FILE="./avatar-placeholder.webp"
HASH=$(sha256sum $FILE | awk '{print $1}')

# Generate nostr auth
AUTH=$(./create_auth.sh upload $HASH)

# Upload
DESCRIPTOR=$(curl -s --data-binary @"$FILE" -X PUT --header "$AUTH" http://127.0.0.1:8089/upload)
if [ $? -ne 0 ] ; then
    echo "FAILED: Curl (uploading) exited with a non-zero status"
    exit 1
fi
echo "PASS:  FILE UPLOADED"

# Extract the sha256 and compare it
DHASH=$(echo "$DESCRIPTOR" | jq -r .sha256)
if [ $? -ne 0 ] ; then
    echo "FAILED: jq failed extracting sha256 from descriptor"
    exit 1
fi
if [ "$HASH" != "$DHASH" ] ; then
    echo "returned descriptor 'sha256' does not match the hash"
fi
echo "PASS:  DESCRIPTOR HASH MATCHES"

# Extract the URL for download
URL=$(echo "$DESCRIPTOR" | jq -r .url)
if [ $? -ne 0 ] ; then
    echo "FAILED: jq failed extracting url from descriptor"
    exit 1
fi

# DOWNLOAD TEST -----------

curl -s "$URL" > downloaded
if [ $? -ne 0 ] ; then
    echo "FAILED: Curl (downloading) exited with a non-zero status"
    exit 1
fi
echo "PASS:  FILE DOWNLOADED"

# Compare the files
if cmp -s "$FILE" downloaded; then
    echo "PASS:  THE DOWNLOADED FILE MATCHES THE UPLOADED FILE"
else
    echo "FAIL:  THE DOWNLOADED FILE DOES NOT MATCH THE UPLOADED FILE"
fi

echo "end."
exit 0
