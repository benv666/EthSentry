# Eth Sentry

Monitoring and alerting bot for your Ethereum validators and underlying node(s).
Inspired by https://github.com/drjmz/ValMonBot

NOTE: This is very early stage - not production ready yet.
Continue on your own risk!

And yeah, AI is helping, I'm lazy ;)

# Purpose

The main purpose of this bot is to send you notifications/alerts when something is up with your setup.
Second, it can inform you of upcoming/ongoing events such as Sync Committee's and block proposals.

# Installation/Setup

At some point it would be nice to have this added as RocketPool/Hyperdrive addon.
Until then:
```
cp .env.template .env
vim .env
# adjust values
```
In case your BN/EC is based on the hyperdrive or rocketpool stack, you might want to add their networks:
```
vim docker-compose.yml
# uncomment hyperdrive or rocketpool net lines
```

See below on where to grab these values.

## Obtaining values

### Telegram Chat ID

First, setup a Telegram Chat Bot. Message @BotFather, create a new bot, obtain the Token.
Then, message that newly created bot to create a Chat so we can grab the ID.
Easiest is putting the token in your .env file and running the included script:
```
$ bash scripts/getchatid.sh
123465
```
Or you can run the curl to `https://api.telegram.org/bot${TOKEN}/getUpdates` manually and figure out the Chat ID from that response.

### Node URLs

<TODO> - might add autodetection

### Validator Indices

For the list of validator indices, in case your run hyperdrive stakewise:
```
hyperdrive sw v s | grep -o "Index [0-9]\+" | awk '{print $2;}' | paste -sd,
1234,12345,2345,63431
```

## Environment Variables

<details>
<summary><strong>Required</strong></summary>

| Variable            | Description                    | Example                                      |
|---------------------|--------------------------------|----------------------------------------------|
| `TELEGRAM_BOT_TOKEN`| Your Telegram bot token        | `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`  |
| `TELEGRAM_CHAT_ID`  | Chat ID where to send messages | `-1001234567890`                             |

</details>

<details>
<summary><strong>Optional</strong></summary>

| Variable                   | Default                 | Description                                   |
|----------------------------|-------------------------|-----------------------------------------------|
| `BEACON_NODE_URL`          | `http://localhost:5052` | Beacon node API endpoint                      |
| `EXECUTION_NODE_URL`       | `http://localhost:8545` | Execution client RPC endpoint                 |
| `VALIDATOR_INDICES`        | *None*                  | Comma-separated validator indices             |
| `CHECK_INTERVAL`           | `5`                     | Minutes between checks                        |
| `PROPOSAL_LOOKAHEAD`       | `2`                     | Epochs to look ahead for proposals            |
| `SYNC_COMMITTEE_LOOKAHEAD` | `1`                     | Epochs to look ahead for sync committee       |

</details>

# Execution

When all values have been added and you adjusted your networks, simply start it up with:
```
docker compose up -d
```
You should receive your first notifications immediately.
In case the messages indicate connection issues, fix the `docker-compose.yml` and `.env` files, and run above command again until success.

# Warning

Eth Sentry can also fail.
E.g. if your internet goes out this won't work.
If your node reboots it might also not come up. Be sure to plan for these events.
Have some form of external monitoring in place.

# WIP

Work In Progress, I'm not responsible for your stuff catching fire, etc.

# TODO / Future work (concepts)

- rpl/hyperdrive auto detection
- rpl/hyperdrive addon
- fallbacks
- shoutrrr support
- prometheus metrics
- ascii cinema style intro for this document
- auto validator/BN/EC detection
