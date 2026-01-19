# Fumescraper
Fumescraper is an automated CVE monitoring and alerting tool that fetches the latest vulnerabilities from multiple security data sources and posts them directly to a Discord webhook.

It is designed for security researchers, developers, and anyone who wants to stay up‑to‑date with newly disclosed CVEs in real time.

# Cloning
```
git clone https://github.com/hacker3983/fumescraper
```

# Setup
1. get an API key from NVD API:
https://nvd.nist.gov/developers/request-an-api-key

2. Create a discord server and get a webhook

3. Run the following commands in a terminal
```
cd fumescraper && python3 main.py
```

4. After running fumescraper for the first time you will paste the webhook url and the nvd api key
you will not need to do this again.

5. fumescraper will start scraping data and automatically send it to the discord webhook provided

# Usage
```
python3 main.py
```

# Screenshots
![screenshot 1](Screenshots/menu.png)

![screenshot 2](./Screenshots/proof.png)

