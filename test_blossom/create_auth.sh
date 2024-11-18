#!/bin/bash

PUBKEY=12bb541d03bfc3cab0f4a8e4db28947f60faae6fca4e315eb27f809c6eff9a0b
PRIVKEY=b4a98d96270b6cd30c80e4fd594461d2b22d8dbcfbcd1f7b11bf0ef2b028a56b
AUTH_EXPIRATION=1900000000

VERB=$1
HASH=$2

if [ x$VERB = x ] ; then
    echo "USAGE:  create_auth.sh VERB HASH"
    exit 1
fi

if [ x$HASH = x ] ; then
    echo "USAGE:  create_auth.sh VERB HASH"
    exit 1
fi

PRE_EVENT='{"pubkey": "'$PUBKEY'", "kind": 24242, "created_at": 0, "tags": [["expiration","'$AUTH_EXPIRATION'"], ["t","'$VERB'"], ["x","'$HASH'"]], "content":""}'

EVENT=$(echo "$PRE_EVENT" | nak event --sec $PRIVKEY)

EVENT_BASE64=$(echo $EVENT | base64 -w 0)

echo "Authorization: Nostr $EVENT_BASE64"
