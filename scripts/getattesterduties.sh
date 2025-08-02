#!/bin/bash
BN_URL="$(cat .env | sed -n 's/^BEACON_NODE_URL=//p')"
if [ $# -le 0 ]; then
	echo Syntax: $0 validators
	echo E.g.: $0 1234 32456
	exit 1
fi
JVALS=$(printf '"%s",' "$@")
JVALS="[${JVALS%,}]"
EPOCH="$((`curl -s -X GET "${BN_URL}/eth/v1/beacon/headers/head" | jq .data.header.message.slot -r` / 32))"
printf "Epoch %s, validators %s\n" "$EPOCH" "$JVALS"
curl -s  --header 'Content-Type: application/json'  --data "$JVALS" "${BN_URL}/eth/v1/validator/duties/attester/$EPOCH"  | jq
