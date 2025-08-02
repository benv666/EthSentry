#!/bin/bash
BN_URL="$(cat .env | sed -n 's/^BEACON_NODE_URL=//p')"
if [ $# -le 0 ]; then
	echo "Syntax: $0 [slotno]"
	echo E.g.: $0 12276425
	exit 1
fi
#EPOCH="$((`curl -s -X GET "${BN_URL}/eth/v1/beacon/headers/head" | jq .data.header.message.slot -r` / 32))"
SLOT=${1:-$((`curl -s -X GET "${BN_URL}/eth/v1/beacon/headers/head" | jq .data.header.message.slot -r`))}
printf "Slot %s:\n" "$SLOT"
curl -s  --header 'Content-Type: application/json' "${BN_URL}/eth/v2/beacon/blocks/$SLOT"  | jq
