"""
Configuration constants for Glance.
Contains patterns, URLs, and settings for malware detection.
"""

import re
from pathlib import Path

# Export folder for intercept reports
EXPORT_FOLDER = Path("./exports")
EXPORT_FOLDER.mkdir(exist_ok=True)

# Strict mode blocks ALL hosts that don't trust the certificate
STRICT_MODE = False

# Enhanced Security Settings
LOG_ALL_CONNECTIONS = True  # Log every connection for behavioral analysis
BEHAVIORAL_ANALYSIS = True  # Track patterns for unknown C2 detection
BLOCK_SUSPICIOUS_BEHAVIOR = True  # Block requests with suspicious heuristics

# Heuristic Detection Thresholds
MAX_POST_BODY_SIZE = 500000  # 500KB - flag large data exfiltration
MAX_REQUEST_FREQUENCY = 50  # Max requests per minute to same unknown host
SUSPICIOUS_PORT_RANGES = [
    2404,
    4444,
    5555,
    6666,
    7080,
    7443,
    7777,
    8080,
    8090,
    8443,
    8848,
    8888,
    9999,
    60000,
]  # Common C2 ports

# Regex patterns for detecting tokens and API keys
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

# URLs that trigger suspicious activity detection
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

# Suspicious indicators for unknown C2 servers
SUSPICIOUS_INDICATORS = [
    "/api/collect",
    "/api/exfil",
    "/upload",
    "/submit",
    "/log",
    "/data",
    "/beacon",
    "/c2",
    "/command",
    "/heartbeat",
    "base64",  # Base64 in URL often indicates obfuscation
]

# Suspicious headers that indicate malware behavior
SUSPICIOUS_HEADERS = [
    "x-session-token",
    "x-auth-token",
    "x-api-key",
    "x-hwid",
    "x-client-id",
    "x-victim-id",
]

# Hosts that bypass MITM (legitimate Minecraft infrastructure)
IGNORE_HOSTS = [
    "files.minecraftforge.net",
    "launchermeta.mojang.com",
    "piston-meta.mojang.com",
    "piston-data.mojang.com",
    "launcher.mojang.com",
    "libraries.minecraft.net",
    "resources.download.minecraft.net",
]
