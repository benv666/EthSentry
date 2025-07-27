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
| `FALLBACK_BEACON_NODE_URL` | *None*                  | Fallback beacon node API endpoint             |
| `FALLBACK_EXECUTION_NODE_URL` | *None*                  | Fallback execution node API endpoint             |
| `VALIDATOR_INDICES`        | *None*                  | Comma-separated validator indices             |
| `CHECK_INTERVAL`           | `5`                     | Minutes between checks                        |
| `PROPOSAL_LOOKAHEAD`       | `2`                     | Epochs to look ahead for proposals            |
| `SYNC_COMMITTEE_LOOKAHEAD` | `1`                     | Epochs to look ahead for sync committee       |

</details>

# Docker Deployment

When all values have been added and you adjusted your networks, simply start it up with:
```
docker compose up -d
```
You should receive your first notifications immediately.
In case the messages indicate connection issues, fix the `docker-compose.yml` and `.env` files, and run above command again until success.


```bash
# Standard deployment
docker compose up -d

# With Prometheus metrics
echo "ENABLE_PROMETHEUS=true" >> .env
vim docker-compose.yaml  # Uncomment ports section
docker compose up -d
```

# 📱 Telegram Commands

The bot supports interactive commands for detailed monitoring:

- `/help` - Show all available commands
- `/status` - Current system and validator status
- `/validator <index>` - Detailed validator information and performance
- `/epoch [number]` - Epoch summary (defaults to last completed epoch)

### Example Interactions

```
/validator 12345
🔍 Validator 12345 Details

Status: active_ongoing
Balance: 32.1234 ETH
Recent Performance (last 5 epochs):
• Attestations: 5/5
• Last Proposal: Slot 8234567
• Last Proposal Reward: 0.0234 ETH

/epoch
📊 Epoch 12345 Summary
Successful Proposals: 2
Missed Attestations: 0
Total Rewards: 0.0456 ETH
Performance: 100%
```

# 🔔 Notification Types

## Real-time Alerts
- **Successful Proposals**: "🎯 Block Proposed! Validator 123, Slot 456, Reward: 0.02 ETH"
- **Missed Attestations**: "⚠️ Missed Attestation - Validator 123, Epoch 45"
- **State Changes**: "⚠️ Validator State Change - 123: active_ongoing → exiting"
- **Node Issues**: "🚨 Beacon Node Error - Connection failed"

## Scheduled Reports
- **Epoch Summaries**: Comprehensive performance after each epoch
- **Status Summaries**: Periodic system health reports
- **Upcoming Duties**: Advance notice of proposals and sync committee

# 📈 Prometheus Metrics

Enable with `ENABLE_PROMETHEUS=true` and access metrics at `http://localhost:8080/metrics`

## Available Metrics
- `eth_validator_status` - Validator status (active/inactive)
- `eth_validator_balance_gwei` - Current validator balances
- `eth_node_status` - Node sync status
- `eth_attestations_total` - Attestation success/failure counts
- `eth_proposals_total` - Proposal success counts
- `eth_proposal_reward_gwei` - Proposal rewards
- `eth_current_epoch` - Current epoch number


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
[x] fallbacks
[x] shoutrrr support
[x] prometheus metrics
- ascii cinema style intro for this document
- auto validator/BN/EC detection
