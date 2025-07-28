#!/bin/bash
TOKEN="$(cat .env | sed -n 's/^TELEGRAM_BOT_TOKEN=//p')"
curl -s https://api.telegram.org/bot${TOKEN}/getUpdates?offset=-1 | jq -r '.result[0].message.text'
