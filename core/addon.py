"""
mitmproxy addon for Glance.
Intercepts and analyzes HTTPS traffic for suspicious activity.

This module is loaded directly by mitmproxy, so it must use absolute imports
or define its own constants (no relative imports work when loaded as a script).
"""

import re
import json
import hashlib
from datetime import datetime
from pathlib import Path

from mitmproxy import http, ctx

# Configuration constants (duplicated here because mitmproxy loads this as a standalone script)
EXPORT_FOLDER = Path("./exports")
EXPORT_FOLDER.mkdir(exist_ok=True)

STRICT_MODE = False

PATTERNS = {
    "discord_token": re.compile(
        r"[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{38,}", re.IGNORECASE
    ),
    "discord_token_mfa": re.compile(r"mfa\.[A-Za-z0-9_-]{84,}", re.IGNORECASE),
    "discord_webhook": re.compile(
        r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
    ),
    "telegram_bot_token": re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    "api_key": re.compile(
        r'(?i)(api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,100})["\']?'
    ),
}

SUSPICIOUS_URLS = [
    "api.discord.com/api/webhooks/",
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
    "api.telegram.org/bot",
    "webhook",
    "pastebin.com",
    "hastebin.com",
    "transfer.sh",
    "api.ipify.org",
    "github.com",
    "raw.githubusercontent.com",
]

IGNORE_HOSTS = [
    "files.minecraftforge.net",
    "launchermeta.mojang.com",
    "piston-meta.mojang.com",
    "piston-data.mojang.com",
    "launcher.mojang.com",
    "libraries.minecraft.net",
    "resources.download.minecraft.net",
]


class GlanceAddon:
    """mitmproxy addon that intercepts suspicious requests."""

    def tls_clienthello(self, data):
        """Handle TLS client hello to bypass or block certain hosts."""
        client_hello = data.context.client.sni
        if client_hello:
            if STRICT_MODE:
                ctx.log.warn(
                    f"[!] STRICT MODE: blocking {client_hello} (no trusted certificate)"
                )
                return

            for ignore_host in IGNORE_HOSTS:
                if ignore_host in client_hello:
                    ctx.log.warn(f"[!] BYPASSED WITHOUT DECRYPTION: {client_hello}")
                    ctx.log.warn(
                        "    [!] Malware could download payload from this domain!"
                    )
                    self._log_bypassed_connection(client_hello)
                    data.ignore_connection = True
                    return

    def _log_bypassed_connection(self, hostname):
        """Log connections that bypass MITM interception."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = EXPORT_FOLDER / "bypassed_connections.log"

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] BYPASSED (NO MITM): {hostname}\n")
            f.write(
                "  [!] Connection bypassed without decryption - content not verified!\n"
            )
            f.write("  [i] Enable STRICT_MODE=True to block\n\n")

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and analyze HTTP requests."""
        request = flow.request
        url = request.pretty_url
        method = request.method
        headers = dict(request.headers)
        body = request.text or ""

        if self._is_suspicious(url, body):
            ctx.log.warn(f"[!!!] SUSPICIOUS REQUEST: {method} {url}")
            self._handle_suspicious(flow, method, url, headers, body)

    def _is_suspicious(self, url, body):
        """Check if a request is suspicious based on URL or content."""
        for pattern in SUSPICIOUS_URLS:
            if pattern in url.lower():
                return True

        for pattern_name, pattern in PATTERNS.items():
            if re.search(pattern, body):
                return True

        return False

    def _extract_tokens(self, text):
        """Extract tokens and API keys from text."""
        found = {}
        for name, pattern in PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                cleaned = [m[1] if isinstance(m, tuple) else m for m in matches]
                found[name] = list(set(cleaned))
        return found

    def _handle_suspicious(self, flow, method, url, headers, body):
        """Handle a suspicious request by logging and blocking it."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        full_text = f"{url}\n{body}"
        found_tokens = self._extract_tokens(full_text)
        content_hash = hashlib.md5((url + body).encode()).hexdigest()[:8]
        base_name = f"{timestamp}_{content_hash}"

        # Save human-readable report
        txt_file = EXPORT_FOLDER / f"{base_name}_intercept.txt"
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write("GLANCE - INTERCEPT REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Method: {method}\n")
            f.write(f"URL: {url}\n")
            f.write(f"User-Agent: {headers.get('User-Agent', 'N/A')}\n\n")

            if found_tokens:
                f.write("[!!!] TOKENS/KEYS DETECTED:\n")
                for token_type, tokens in found_tokens.items():
                    f.write(f"  - {token_type.upper()} ({len(tokens)}): \n")
                    for token in tokens:
                        f.write(f"    > {token}\n")
                f.write("\n")

            f.write("Headers:\n")
            f.write(json.dumps(headers, indent=2, ensure_ascii=False))
            f.write("\n\nRequest Body:\n")
            f.write(body if body else "(empty)")

        # Save machine-readable JSON
        json_file = EXPORT_FOLDER / f"{base_name}_intercept.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": body,
                    "extracted_tokens": found_tokens,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        ctx.log.info(f"[i] Report saved: {txt_file.name} + {json_file.name}")

        # Block the request with a fake success response
        flow.response = http.Response.make(
            200,
            b'{"success": true, "message": "Data received safely :)"}',
            {"Content-Type": "application/json"},
        )
        ctx.log.warn("[OK] REQUEST BLOCKED - token is safe!")


# Addon instance for mitmproxy
addons = [GlanceAddon()]
