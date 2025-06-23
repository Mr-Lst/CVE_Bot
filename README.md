# CVE Bot

CVE Bot is an automated tool designed to fetch recent CVEs (Common Vulnerabilities and Exposures) from the NVD API and deliver them directly to a Discord channel via webhook integration. This helps security teams, researchers, and enthusiasts stay up to date with the latest vulnerabilities in real-time.

# Features

- Retrieves newly published CVEs every 60 seconds
- Filters out already sent CVEs to avoid duplicates
- Provides enriched embeds including:
  - CVE description and severity (CVSS score)
  - Affected products
  - CWE reference
  - Key exploitability factors
  - Source references
- Sends CVEs via Discord Webhook with detailed formatting
- Supports .env file for managing API keys and webhooks securely

# Installation

1. Clone the repository:
```Git

   git clone https://github.com/Mr-Lst/cve-bot.git
   cd cve-bot

```

2. Install dependencies:
```pip

   pip install -r requirements.txt

```

3. Create a .env file (or use the default webhook-key.env) and add:

```Edit

   DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
   NVD_API_KEY=your_nvd_api_key   (Optional, but recommended)

```
# Running the Bot

To run the script:
```Run

   python cve_bot.py

```
## The bot will run indefinitely and fetch CVEs every minute.

## Example Output (in Discord)

# Each embed includes:
- CVE ID and title
- Description
- CVSS severity and score
- CWE reference link
- Top 5 affected products
- Key exploitation factors (privileges, complexity, etc.)
- References and publication time

# Notes

- The bot stores already sent CVEs in a sent_cves.json file to prevent duplication.
- You may optionally run this script in a background service or Docker container.

# License

This project is licensed under the MIT License.
