#!/bin/bash
BN_URL="$(cat .env | sed -n 's/^BEACON_NODE_URL=//p')"
if [ $# -le 0 ]; then
	echo "Syntax: $0 [amount] [nextblock]"
	echo "E.g.: $0 5"
	echo " ^- will return 5 proposers for the current epoch"
	echo "E.g.: $0 32 1"
	echo " ^- will return all proposers for the next epoch"
	exit 1
fi
MAX=$1
NEXT=${2:-0}
EPOCH="$((`curl -s -X GET "${BN_URL}/eth/v1/beacon/headers/head" | jq .data.header.message.slot -r` / 32 + $NEXT))"
printf "Epoch %s, %s proposers\n" "$EPOCH" "$MAX"
curl -s  --header 'Content-Type: application/json' "${BN_URL}/eth/v1/validator/duties/proposer/$EPOCH"  | jq -r ".data[].validator_index" | sort -n | head -$MAX
