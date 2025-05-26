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

# ADD ADMIN AS A USER ------------

echo "Adding user..."
PUBKEY=12bb541d03bfc3cab0f4a8e4db28947f60faae6fca4e315eb27f809c6eff9a0b
../target/release/chorus_cmd ./config.toml add_user $PUBKEY 0

# UPLOAD TEST ------------

FILE="./Example.png"
HASH=$(sha256sum $FILE | awk '{print $1}')

# Generate nostr auth
AUTH=$(./create_auth.sh upload $HASH)

# Upload (note we clobber the content type)
DESCRIPTOR=$(curl -vfs --data-binary @"$FILE" -H "Content-Type: " -X PUT --header "$AUTH" http://127.0.0.1:8089/upload)
if [ $? -ne 0 ] ; then
    echo "FAILED: Curl (uploading) exited with a non-zero status"
    exit 1
fi
echo "PASS:  FILE UPLOADED"

## FIXME check for 4xx and 5xx error codes


# Extract the sha256 and compare it
DHASH=$(echo "$DESCRIPTOR" | jq -r .sha256)
if [ $? -ne 0 ] ; then
    echo "FAILED: jq failed extracting sha256 from descriptor"
    exit 1
fi
if [ "$HASH" != "$DHASH" ] ; then
    echo "returned descriptor 'sha256' does not match the hash"
    exit 1
fi
echo "PASS:  DESCRIPTOR HASH MATCHES"

# Extract the URL for download
URL=$(echo "$DESCRIPTOR" | jq -r .url)
if [ $? -ne 0 ] ; then
    echo "FAILED: jq failed extracting url from descriptor"
    exit 1
fi

echo "Descriptor URL = $URL"

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
