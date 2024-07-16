# Cloudflare Firewall Rules for Security Bypasses by John D Cyber
### Find more stuff like this on ***(johndcyber.com)***

## Overview
This document outlines a set of Cloudflare firewall rules designed to mitigate various security bypass attempts such as Cross-Site Scripting (XSS), SQL Injection (SQLi), and Remote Code Execution (RCE). Security engineers can use these rules to enhance the security of their web applications by blocking common attack patterns.

## Firewall Rules

### Cross-Site Scripting (XSS) (medium.com/@the_harvester)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query contains '<script>') or (http.request.uri.path contains '<script>')`
- **Description:** Block requests containing XSS attack patterns in the query string or path.

### Reflected XSS (RXSS) (cyberweapons.medium.com/reflected-xss)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query contains '<script>') or (http.request.uri.query contains 'onerror=') or (http.request.uri.path contains '<script>')`
- **Description:** Block common RXSS attack patterns in query string or path.

### SQL Injection (SQLi) (medium.com/@amitdutta6026)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query matches '(?i)\b(select|union|insert|update|delete|drop|alter|exec|execute)\b') or (http.request.uri.path matches '(?i)\b(select|union|insert|update|delete|drop|alter|exec|execute)\b')`
- **Description:** Block requests containing common SQLi attack keywords.

### Session ID from XSS (medium.com/@mayankchoubey)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query contains 'SID=') and (http.request.uri.query contains '<script>')`
- **Description:** Block requests trying to steal session IDs using XSS.

### Cloudflare Bypass in Microsoft (royzsec.medium.com/cloudflare-byp)
- **Rule Action:** Challenge
- **Expression:** `(http.request.uri.path contains '/.well-known/') and (http.request.headers['User-Agent'] matches '(?i)python|curl|wget')`
- **Description:** Challenge requests accessing well-known paths with suspicious user agents.

### Chatbot XSS (medium.com/@cyberweapons/chatbot-xss)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query contains '<script>') and (http.request.uri.path contains '/chatbot')`
- **Description:** Block XSS attacks targeting chatbot endpoints.

### Origin IP (medium.com/@b.jaga1712200)
- **Rule Action:** Block
- **Expression:** `(http.request.headers['Host'] eq 'your-origin-ip')`
- **Description:** Block requests directly accessing the origin IP.

### Admin Path Bypass (medium.com/@friendly_/byp)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.path contains '/admin') and (http.request.headers['User-Agent'] matches '(?i)curl|wget|python')`
- **Description:** Block bypass attempts targeting the admin path with suspicious user agents.

### Login Path Bypass (medium.com/@thorikaz/bypa)
- **Rule Action:** Block
- **Expression:** `(http.request.uri.path contains '/login') and (http.request.headers['User-Agent'] matches '(?i)curl|wget|python')`
- **Description:** Block bypass attempts targeting the login path with suspicious user agents.

### Remote Code Execution (RCE) (medium.com/@alii76tt/remo (CVE-2022-29464))
- **Rule Action:** Block
- **Expression:** `(http.request.uri.query contains 'cmd=') or (http.request.uri.path contains 'cmd=')`
- **Description:** Block RCE attempts by detecting suspicious command injection patterns.

## Implementation Guide

### Step-by-Step Implementation

1. **Login to Cloudflare Dashboard:**
   - Go to the Cloudflare dashboard and select the domain for which you want to implement the firewall rules.

2. **Navigate to Firewall Rules:**
   - In the dashboard, go to the "Firewall" section. Select "Firewall Rules" from the submenu.

3. **Create a New Rule:**
   - Click on the "Create a Firewall Rule" button. Provide a name for your rule, for example, "Block XSS Attacks."

4. **Define the Rule Action and Expression:**
   - In the rule configuration section, define the action (e.g., Block, Challenge) and the expression. Refer to the rules provided above for specific expressions.

### Implementing Rules in Non-Active State

To ensure that these rules do not disrupt legitimate traffic initially, you can implement them in a non-active state for observation:

1. **Set Rule Action to Log:**
   - Instead of setting the rule action to "Block" or "Challenge," set it to "Log." This will log the request details without blocking them, allowing you to monitor the impact of the rule.

2. **Monitor the Logs:**
   - Go to the "Firewall Events" section in the Cloudflare dashboard. Review the logs to see how often the rules are triggered and analyze the nature of the requests being logged.

3. **Adjust Rules if Necessary:**
   - Based on the logs, adjust the rule expressions to fine-tune them and reduce false positives.

4. **Activate the Rules:**
   - Once you are confident that the rules will not block legitimate traffic, change the rule action from "Log" to "Block" or "Challenge" as appropriate.

## API Calls for Postman

### Prerequisites
- **API Token:** Obtain an API token from your Cloudflare account with permissions to manage firewall rules.
- **Zone ID:** Find the Zone ID for the domain where you want to apply these rules.

### Headers
- **Authorization:** Bearer [your-api-token]
- **Content-Type:** application/json

### Base URL
```bash
https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules

###API Call: POST Implementation

```
{
  "action": "block",
  "expression": "(http.request.uri.query contains '<script>') or (http.request.uri.path contains '<script>')",
  "description": "Block requests containing XSS attack patterns in the query string or path.",
  "paused": false,
  "priority": 1,
  "ref": "Block XSS Attacks"
}
```

###Curl Command:
```
curl -X POST "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules" \
     -H "Authorization: Bearer [your-api-token]" \
     -H "Content-Type: application/json" \
     --data '{
       "action": "block",
       "expression": "(http.request.uri.query contains \'<script>\') or (http.request.uri.path contains \'<script>\')",
       "description": "Block requests containing XSS attack patterns in the query string or path.",
       "paused": false,
       "priority": 1,
       "ref": "Block XSS Attacks"
     }'

```






