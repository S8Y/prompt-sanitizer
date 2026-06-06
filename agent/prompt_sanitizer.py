"""Prompt & response sanitization layer for sensitive data protection.

Provides a configurable sanitization layer that sits between user input
and LLM providers. Before sending a prompt to any model, it detects
sensitive data patterns (API keys, emails, tokens, hosts, DB URIs, etc.),
replaces them with safe placeholders, stores the mappings in a local-only
in-memory vault, and restores original values in the model's response.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Email addresses
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# Phone numbers: +<country><number>, with optional formatting chars
_PHONE_RE = re.compile(
    r"(\+[1-9][\d\s\.\-\(\)]{5,20}\d)(?![A-Za-z0-9/])"
)

# API key prefixes (reuses patterns from agent/redact.py)
_API_KEY_PREFIXES = [
    r"sk-[A-Za-z0-9_-]{10,}",           # OpenAI / OpenRouter / Anthropic
    r"sk-ant-[A-Za-z0-9_-]{10,}",        # Anthropic native
    r"ghp_[A-Za-z0-9]{10,}",             # GitHub PAT (classic)
    r"github_pat_[A-Za-z0-9_]{10,}",     # GitHub PAT (fine-grained)
    r"gho_[A-Za-z0-9]{10,}",             # GitHub OAuth access token
    r"ghu_[A-Za-z0-9]{10,}",             # GitHub user-to-server token
    r"ghs_[A-Za-z0-9]{10,}",             # GitHub server-to-server token
    r"ghr_[A-Za-z0-9]{10,}",             # GitHub refresh token
    r"xox[baprs]-[A-Za-z0-9-]{10,}",    # Slack tokens
    r"AIza[A-Za-z0-9_-]{30,}",           # Google API keys
    r"pplx-[A-Za-z0-9]{10,}",           # Perplexity
    r"fal_[A-Za-z0-9_-]{10,}",           # Fal.ai
    r"fc-[A-Za-z0-9]{10,}",             # Firecrawl
    r"gAAAA[A-Za-z0-9_=-]{20,}",        # Codex encrypted tokens
    r"AKIA[A-Z0-9]{16}",                # AWS Access Key ID
    r"sk_live_[A-Za-z0-9]{10,}",        # Stripe secret key (live)
    r"sk_test_[A-Za-z0-9]{10,}",        # Stripe secret key (test)
    r"rk_live_[A-Za-z0-9]{10,}",        # Stripe restricted key
    r"SG\.[A-Za-z0-9_-]{10,}",          # SendGrid API key
    r"hf_[A-Za-z0-9]{10,}",             # HuggingFace token
    r"r8_[A-Za-z0-9]{10,}",             # Replicate API token
    r"npm_[A-Za-z0-9]{10,}",            # npm access token
    r"pypi-[A-Za-z0-9_-]{10,}",         # PyPI API token
    r"dop_v1_[A-Za-z0-9]{10,}",         # DigitalOcean PAT
    r"doo_v1_[A-Za-z0-9]{10,}",         # DigitalOcean OAuth
    r"tvly-[A-Za-z0-9]{10,}",           # Tavily search API key
    r"exa_[A-Za-z0-9]{10,}",            # Exa search API key
    r"gsk_[A-Za-z0-9]{10,}",            # Groq Cloud API key
    r"xai-[A-Za-z0-9]{30,}",            # xAI (Grok) API key
    r"sk_[A-Za-z0-9_]{10,}",            # ElevenLabs TTS key
    r"mem0_[A-Za-z0-9]{10,}",           # Mem0 Platform API key
    r"bb_live_[A-Za-z0-9_-]{10,}",      # BrowserBase
    r"nf_[a-zA-Z0-9]{10,}",                # Netlify access token
    r"dd[ip]_[A-Za-z0-9]{10,}",             # Datadog API/APP key
    r"discord_[A-Za-z0-9]{10,}",            # Discord bot token (partial)
    r"supabase_[A-Za-z0-9]{10,}",           # Supabase service key
    r"sbp_[a-f0-9]{32,}",                   # Sentry auth token
    r"ac_[A-Za-z0-9]{10,}",                 # Coinbase access token
    r"t[12][A-Za-z0-9]{10,}",               # Twilio API key (SID)
    r"pk\.[A-Za-z0-9]{10,}",                # Stripe publishable key
    r"whsec_[A-Za-z0-9]{10,}",              # Stripe webhook secret
    r"ghu_[A-Za-z0-9]{10,}",                # GitHub user token
    r"api-[a-f0-9]{32,}",                   # Algolia API key
    r"sk\.[A-Za-z0-9]{10,}",                # Clerk secret key
    r"FIREBASE_[A-Za-z0-9]{10,}",           # Firebase config key
    r"eyJh[A-Za-z0-9_-]{10,}",              # Additional JWT header pattern
    r"pat_[A-Za-z0-9]{10,}",                # Generic Personal Access Token
]

_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(" + "|".join(_API_KEY_PREFIXES) + r")(?![A-Za-z0-9_-])"
)

# JWT tokens: header.payload.signature
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}"
    r"(?:\.[A-Za-z0-9_=-]{4,}){0,2}"
)

# Private key blocks (PEM format)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"
)

# SSH private keys (OpenSSH format)
_SSH_KEY_RE = re.compile(
    r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----"
)

# Database connection strings: protocol://user:PASSWORD@host
_DB_CONNSTR_RE = re.compile(
    r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:]+:)([^@]+)(@)",
    re.IGNORECASE,
)

# Private/internal IP addresses
_PRIVATE_IP_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Internal hostnames (*.internal, *.local, *.lan, *.corp, *.private)
_INTERNAL_HOST_RE = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)"
    r"(?:"
    r"internal|local|lan|private|corp|intranet"
    r"|localhost"
    r")"
    r"(?:\.[a-zA-Z]{2,})?"
    r"\b",
    re.IGNORECASE,
)

# URLs with embedded credentials: scheme://user:password@host
_URL_USERINFO_RE = re.compile(
    r"(https?|wss?|ftp)://([^/\s:@]+):([^/\s@]+)@",
)

# ENV assignment patterns: KEY=value where KEY contains a secret-like name
_SECRET_ENV_NAMES_PATTERN = r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)"
_ENV_ASSIGN_RE = re.compile(
    r"([A-Z0-9_]{0,50}" + _SECRET_ENV_NAMES_PATTERN + r"[A-Z0-9_]{0,50})\s*=\s*(['\"]?)(\S+)\2",
)

# JSON field patterns: "apiKey": "value", "token": "value", etc.
_JSON_KEY_NAMES = r"(?:api_?[Kk]ey|token|secret|password|access_token|refresh_token|auth_token|bearer|secret_value|raw_secret|secret_input|key_material)"
_JSON_FIELD_RE = re.compile(
    r'("' + _JSON_KEY_NAMES + r'")\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)

# Authorization headers
_AUTH_HEADER_RE = re.compile(
    r"(Authorization:\s*Bearer\s+)(\S+)",
    re.IGNORECASE,
)

# Telegram bot tokens: <digits>:<token>
_TELEGRAM_RE = re.compile(
    r"(bot)?(\d{8,}):([-A-Za-z0-9_]{30,})",
)

# Cloud metadata endpoints
_CLOUD_METADATA_RE = re.compile(
    r"(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com"
    r"|metadata\.amazonaws\.com)"
)

# AWS ARN
_AWS_ARN_RE = re.compile(
    r"arn:(aws|aws-cn|aws-us-gov):[a-z0-9-]+:(?:[a-z0-9-]*:)?(?:\d{12}:)?:?[a-z0-9_/.-]+"
)

# URLs — full http/https links (excludes brackets to avoid vault chaining)
_URL_RE = re.compile(
    r"https?://[^\s<>{}|\\^`\[\]]+",
)

# Domain names (FQDNs with 3+ labels, avoiding file extension false positives).
# Negative lookbehind prevents matching hostnames inside ``http://`` /
# ``https://`` URLs that were intentionally left unchanged (safe domains).
_DOMAIN_RE = re.compile(
    r"\b(?<!://)((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,6})\b"
)

# IANA Top-Level Domains (https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
# Version 2026060600 — 1437 entries — validates URL/domain detection against real TLDs
_TLDS = frozenset({
    "aaa", "aarp", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi", "ac", "academy", "accenture",
    "accountant", "accountants", "aco", "actor", "ad", "ads", "adult", "ae", "aeg", "aero", "aetna", "af",
    "afl", "africa", "ag", "agakhan", "agency", "ai", "aig", "airbus", "airforce", "airtel", "akdn", "al",
    "alibaba", "alipay", "allfinanz", "allstate", "ally", "alsace", "alstom", "am", "amazon", "americanexpress", "americanfamily", "amex",
    "amfam", "amica", "amsterdam", "analytics", "android", "anquan", "anz", "ao", "aol", "apartments", "app", "apple",
    "aq", "aquarelle", "ar", "arab", "aramco", "archi", "army", "arpa", "art", "arte", "as", "asda",
    "asia", "associates", "at", "athleta", "attorney", "au", "auction", "audi", "audible", "audio", "auspost", "author",
    "auto", "autos", "aw", "aws", "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex",
    "band", "bank", "bar", "barcelona", "barclaycard", "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern",
    "bb", "bbc", "bbt", "bbva", "bcg", "bcn", "bd", "be", "beats", "beauty", "beer", "berlin",
    "best", "bestbuy", "bet", "bf", "bg", "bh", "bharti", "bi", "bible", "bid", "bike", "bing",
    "bingo", "bio", "biz", "bj", "black", "blackfriday", "blockbuster", "blog", "bloomberg", "blue", "bm", "bms",
    "bmw", "bn", "bnpparibas", "bo", "boats", "boehringer", "bofa", "bom", "bond", "boo", "book", "booking",
    "bosch", "bostik", "boston", "bot", "boutique", "box", "br", "bradesco", "bridgestone", "broadway", "broker", "brother",
    "brussels", "bs", "bt", "build", "builders", "business", "buy", "buzz", "bv", "bw", "by", "bz",
    "bzh", "ca", "cab", "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "canon", "capetown",
    "capital", "capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "cash",
    "casino", "cat", "catering", "catholic", "cba", "cbn", "cbre", "cc", "cd", "center", "ceo", "cern",
    "cf", "cfa", "cfd", "cg", "ch", "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai",
    "christmas", "chrome", "church", "ci", "cipriani", "circle", "cisco", "citadel", "citi", "citic", "city", "ck",
    "cl", "claims", "cleaning", "click", "clinic", "clinique", "clothing", "cloud", "club", "clubmed", "cm", "cn",
    "co", "coach", "codes", "coffee", "college", "cologne", "com", "commbank", "community", "company", "compare", "computer",
    "comsec", "condos", "construction", "consulting", "contact", "contractors", "cooking", "cool", "coop", "corsica", "country", "coupon",
    "coupons", "courses", "cpa", "cr", "credit", "creditcard", "creditunion", "cricket", "crown", "crs", "cruise", "cruises",
    "cu", "cuisinella", "cv", "cw", "cx", "cy", "cymru", "cyou", "cz", "dad", "dance", "data",
    "date", "dating", "datsun", "day", "dclk", "dds", "de", "deal", "dealer", "deals", "degree", "delivery",
    "dell", "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds", "diet",
    "digital", "direct", "directory", "discount", "discover", "dish", "diy", "dj", "dk", "dm", "dnp", "do",
    "docs", "doctor", "dog", "domains", "dot", "download", "drive", "dtv", "dubai", "dupont", "durban", "dvag",
    "dvr", "dz", "earth", "eat", "ec", "eco", "edeka", "edu", "education", "ee", "eg", "email",
    "emerck", "energy", "engineer", "engineering", "enterprises", "epson", "equipment", "er", "ericsson", "erni", "es", "esq",
    "estate", "et", "eu", "eurovision", "eus", "events", "exchange", "expert", "exposed", "express", "extraspace", "fage",
    "fail", "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers", "fashion", "fast", "fedex", "feedback",
    "ferrari", "ferrero", "fi", "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone", "firmdale",
    "fish", "fishing", "fit", "fitness", "fj", "fk", "flickr", "flights", "flir", "florist", "flowers", "fly",
    "fm", "fo", "foo", "food", "football", "ford", "forex", "forsale", "forum", "foundation", "fox", "fr",
    "free", "fresenius", "frl", "frogans", "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi",
    "ga", "gal", "gallery", "gallo", "gallup", "game", "games", "gap", "garden", "gay", "gb", "gbiz",
    "gd", "gdn", "ge", "gea", "gent", "genting", "george", "gf", "gg", "ggee", "gh", "gi",
    "gift", "gifts", "gives", "giving", "gl", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh",
    "gmo", "gmx", "gn", "godaddy", "gold", "goldpoint", "golf", "goodyear", "goog", "google", "gop", "got",
    "gov", "gp", "gq", "gr", "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "gs",
    "gt", "gu", "gucci", "guge", "guide", "guitars", "guru", "gw", "gy", "hair", "hamburg", "hangout",
    "haus", "hbo", "hdfc", "hdfcbank", "health", "healthcare", "help", "helsinki", "here", "hermes", "hiphop", "hisamitsu",
    "hitachi", "hiv", "hk", "hkt", "hm", "hn", "hockey", "holdings", "holiday", "homedepot", "homegoods", "homes",
    "homesense", "honda", "horse", "hospital", "host", "hosting", "hot", "hotels", "hotmail", "house", "how", "hr",
    "hsbc", "ht", "hu", "hughes", "hyatt", "hyundai", "ibm", "icbc", "ice", "icu", "id", "ie",
    "ieee", "ifm", "ikano", "il", "im", "imamat", "imdb", "immo", "immobilien", "in", "inc", "industries",
    "infiniti", "info", "ing", "ink", "institute", "insurance", "insure", "int", "international", "intuit", "investments", "io",
    "ipiranga", "iq", "ir", "irish", "is", "ismaili", "ist", "istanbul", "it", "itau", "itv", "jaguar",
    "java", "jcb", "je", "jeep", "jetzt", "jewelry", "jio", "jll", "jm", "jmp", "jnj", "jo",
    "jobs", "joburg", "jot", "joy", "jp", "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi", "ke",
    "kerryhotels", "kerryproperties", "kfh", "kg", "kh", "ki", "kia", "kids", "kim", "kindle", "kitchen", "kiwi",
    "km", "kn", "koeln", "komatsu", "kosher", "kp", "kpmg", "kpn", "kr", "krd", "kred", "kuokgroup",
    "kw", "ky", "kyoto", "kz", "la", "lacaixa", "lamborghini", "lamer", "land", "landrover", "lanxess", "lasalle",
    "lat", "latino", "latrobe", "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc", "lefrak", "legal",
    "lego", "lexus", "lgbt", "li", "lidl", "life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited",
    "limo", "lincoln", "link", "live", "living", "lk", "llc", "llp", "loan", "loans", "locker", "locus",
    "lol", "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "lr", "ls", "lt", "ltd", "ltda",
    "lu", "lundbeck", "luxe", "luxury", "lv", "ly", "ma", "madrid", "maif", "maison", "makeup", "man",
    "management", "mango", "map", "market", "marketing", "markets", "marriott", "marshalls", "mattel", "mba", "mc", "mckinsey",
    "md", "me", "med", "media", "meet", "melbourne", "meme", "memorial", "men", "menu", "merck", "merckmsd",
    "mg", "mh", "miami", "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mk", "ml", "mlb",
    "mls", "mm", "mma", "mn", "mo", "mobi", "mobile", "moda", "moe", "moi", "mom", "monash",
    "money", "monster", "mormon", "mortgage", "moscow", "moto", "motorcycles", "mov", "movie", "mp", "mq", "mr",
    "ms", "msd", "mt", "mtn", "mtr", "mu", "museum", "music", "mv", "mw", "mx", "my",
    "mz", "na", "nab", "nagoya", "name", "navy", "nba", "nc", "ne", "nec", "net", "netbank",
    "netflix", "network", "neustar", "new", "news", "next", "nextdirect", "nexus", "nf", "nfl", "ng", "ngo",
    "nhk", "ni", "nico", "nike", "nikon", "ninja", "nissan", "nissay", "nl", "no", "nokia", "norton",
    "now", "nowruz", "nowtv", "np", "nr", "nra", "nrw", "ntt", "nu", "nyc", "nz", "obi",
    "observer", "office", "okinawa", "olayan", "olayangroup", "ollo", "om", "omega", "one", "ong", "onl", "online",
    "ooo", "open", "oracle", "orange", "org", "organic", "origins", "osaka", "otsuka", "ott", "ovh", "pa",
    "page", "panasonic", "paris", "pars", "partners", "parts", "party", "pay", "pccw", "pe", "pet", "pf",
    "pfizer", "pg", "ph", "pharmacy", "phd", "philips", "phone", "photo", "photography", "photos", "physio", "pics",
    "pictet", "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "pk", "pl", "place", "play",
    "playstation", "plumbing", "plus", "pm", "pn", "pnc", "pohl", "poker", "politie", "porn", "post", "pr",
    "praxi", "press", "prime", "pro", "prod", "productions", "prof", "progressive", "promo", "properties", "property", "protection",
    "pru", "prudential", "ps", "pt", "pub", "pw", "pwc", "py", "qa", "qpon", "quebec", "quest",
    "racing", "radio", "re", "read", "realestate", "realtor", "realty", "recipes", "red", "redumbrella", "rehab", "reise",
    "reisen", "reit", "reliance", "ren", "rent", "rentals", "repair", "report", "republican", "rest", "restaurant", "review",
    "reviews", "rexroth", "rich", "richardli", "ricoh", "ril", "rio", "rip", "ro", "rocks", "rodeo", "rogers",
    "room", "rs", "rsvp", "ru", "rugby", "ruhr", "run", "rw", "rwe", "ryukyu", "sa", "saarland",
    "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung", "sandvik", "sandvikcoromant", "sanofi", "sap", "sarl",
    "sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "scb", "schaeffler", "schmidt", "scholarships", "school",
    "schule", "schwarz", "science", "scot", "sd", "se", "search", "seat", "secure", "security", "seek", "select",
    "sener", "services", "seven", "sew", "sex", "sexy", "sfr", "sg", "sh", "shangrila", "sharp", "shell",
    "shia", "shiksha", "shoes", "shop", "shopping", "shouji", "show", "si", "silk", "sina", "singles", "site",
    "sj", "sk", "ski", "skin", "sky", "skype", "sl", "sling", "sm", "smart", "smile", "sn",
    "sncf", "so", "soccer", "social", "softbank", "software", "sohu", "solar", "solutions", "song", "sony", "soy",
    "spa", "space", "sport", "spot", "sr", "srl", "ss", "st", "stada", "staples", "star", "statebank",
    "statefarm", "stc", "stcgroup", "stockholm", "storage", "store", "stream", "studio", "study", "style", "su", "sucks",
    "supplies", "supply", "support", "surf", "surgery", "suzuki", "sv", "swatch", "swiss", "sx", "sy", "sydney",
    "systems", "sz", "tab", "taipei", "talk", "taobao", "target", "tatamotors", "tatar", "tattoo", "tax", "taxi",
    "tc", "tci", "td", "tdk", "team", "tech", "technology", "tel", "temasek", "tennis", "teva", "tf",
    "tg", "th", "thd", "theater", "theatre", "tiaa", "tickets", "tienda", "tips", "tires", "tirol", "tj",
    "tjmaxx", "tjx", "tk", "tkmaxx", "tl", "tm", "tmall", "tn", "to", "today", "tokyo", "tools",
    "top", "toray", "toshiba", "total", "tours", "town", "toyota", "toys", "tr", "trade", "trading", "training",
    "travel", "travelers", "travelersinsurance", "trust", "trv", "tt", "tube", "tui", "tunes", "tushu", "tv", "tvs",
    "tw", "tz", "ua", "ubank", "ubs", "ug", "uk", "unicom", "university", "uno", "uol", "ups",
    "us", "uy", "uz", "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas", "ventures", "verisign",
    "versicherung", "vet", "vg", "vi", "viajes", "video", "vig", "viking", "villas", "vin", "vip", "virgin",
    "visa", "vision", "viva", "vivo", "vlaanderen", "vn", "vodka", "volvo", "vote", "voting", "voto", "voyage",
    "vu", "wales", "walmart", "walter", "wang", "wanggou", "watch", "watches", "weather", "weatherchannel", "webcam", "weber",
    "website", "wed", "wedding", "weibo", "weir", "wf", "whoswho", "wien", "wiki", "williamhill", "win", "windows",
    "wine", "winners", "wme", "woodside", "work", "works", "world", "wow", "ws", "wtc", "wtf", "xbox",
    "xerox", "xihuan", "xin", "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a", "xn--2scrj9c", "xn--30rr7y", "xn--3bst00m", "xn--3ds443g", "xn--3e0b707e", "xn--3hcrj9c",
    "xn--3pxu8k", "xn--42c2d9a", "xn--45br5cyl", "xn--45brj9c", "xn--45q11c", "xn--4dbrk0ce", "xn--4gbrim", "xn--54b7fta0cc", "xn--55qw42g", "xn--55qx5d", "xn--5su34j936bgsg", "xn--5tzm5g",
    "xn--6frz82g", "xn--6qq986b3xl", "xn--80adxhks", "xn--80ao21a", "xn--80aqecdr1a", "xn--80asehdb", "xn--80aswg", "xn--8y0a063a", "xn--90a3ac", "xn--90ae", "xn--90ais", "xn--9dbq2a",
    "xn--9et52u", "xn--9krt00a", "xn--b4w605ferd", "xn--bck1b9a5dre4c", "xn--c1avg", "xn--c2br7g", "xn--cck2b3b", "xn--cckwcxetd", "xn--cg4bki", "xn--clchc0ea0b2g2a9gcd", "xn--czr694b", "xn--czrs0t",
    "xn--czru2d", "xn--d1acj3b", "xn--d1alf", "xn--e1a4c", "xn--eckvdtc9d", "xn--efvy88h", "xn--fct429k", "xn--fhbei", "xn--fiq228c5hs", "xn--fiq64b", "xn--fiqs8s", "xn--fiqz9s",
    "xn--fjq720a", "xn--flw351e", "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--fzys8d69uvgm", "xn--g2xx48c", "xn--gckr3f0f", "xn--gecrj9c", "xn--gk3at1e", "xn--h2breg3eve", "xn--h2brj9c", "xn--h2brj9c8c",
    "xn--hxt814e", "xn--i1b6b1a6a2e", "xn--imr513n", "xn--io0a7i", "xn--j1aef", "xn--j1amh", "xn--j6w193g", "xn--jlq480n2rg", "xn--jvr189m", "xn--kcrx77d1x4a", "xn--kprw13d", "xn--kpry57d",
    "xn--kput3i", "xn--l1acc", "xn--lgbbat1ad8j", "xn--mgb9awbf", "xn--mgba3a3ejt", "xn--mgba3a4f16a", "xn--mgba7c0bbn0a", "xn--mgbaam7a8h", "xn--mgbab2bd", "xn--mgbah1a3hjkrd", "xn--mgbai9azgqp6j", "xn--mgbayh7gpa",
    "xn--mgbbh1a", "xn--mgbbh1a71e", "xn--mgbc0a9azcg", "xn--mgbca7dzdo", "xn--mgbcpq6gpa1a", "xn--mgberp4a5d4ar", "xn--mgbgu82a", "xn--mgbi4ecexp", "xn--mgbpl2fh", "xn--mgbt3dhd", "xn--mgbtx2b", "xn--mgbx4cd0ab",
    "xn--mix891f", "xn--mk1bu44c", "xn--mxtq1m", "xn--ngbc5azd", "xn--ngbe9e0a", "xn--ngbrx", "xn--node", "xn--nqv7f", "xn--nqv7fs00ema", "xn--nyqy26a", "xn--o3cw4h", "xn--ogbpf8fl",
    "xn--otu796d", "xn--p1acf", "xn--p1ai", "xn--pgbs0dh", "xn--pssy2u", "xn--q7ce6a", "xn--q9jyb4c", "xn--qcka1pmc", "xn--qxa6a", "xn--qxam", "xn--rhqv96g", "xn--rovu88b",
    "xn--rvc1e0am3e", "xn--s9brj9c", "xn--ses554g", "xn--t60b56a", "xn--tckwe", "xn--tiq49xqyj", "xn--unup4y", "xn--vermgensberater-ctb", "xn--vermgensberatung-pwb", "xn--vhquv", "xn--vuq861b", "xn--w4r85el8fhu5dnra",
    "xn--w4rs40l", "xn--wgbh1c", "xn--wgbl6a", "xn--xhq521b", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--y9a3aq", "xn--yfro4i67o", "xn--ygbi2ammx", "xn--zfr164b", "xxx", "xyz",
    "yachts", "yahoo", "yamaxun", "yandex", "ye", "yodobashi", "yoga", "yokohama", "you", "youtube", "yt", "yun",
    "za", "zappos", "zara", "zero", "zip", "zm", "zone", "zuerich", "zw",
})


def _valid_tld(tld: str) -> bool:
    """Check if *tld* is a known IANA top-level domain (case-insensitive)."""
    return tld.lower() in _TLDS


# ---------------------------------------------------------------------------
_SSN_RE = re.compile(
    r"\b\d{3}-\d{2}-\d{4}\b"
)

# Credit card numbers (13-19 digits, with Luhn check in _sanitize_credit_card)
_CREDIT_CARD_RE = re.compile(
    r"(?:\b|[^\d])(\d[\d\s-]{13,18}\d)\b"
)

# Bitcoin addresses (legacy P2PKH/P2SH)
_BITCOIN_ADDR_RE = re.compile(
    r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
)

# Bitcoin addresses (Bech32)
_BITCOIN_BECH32_RE = re.compile(
    r"\bbc1[a-z0-9]{39,59}\b"
)

# Ethereum addresses (0x + 40 hex chars)
_ETHEREUM_ADDR_RE = re.compile(
    r"\b0x[a-fA-F0-9]{40}\b"
)

# Discord webhook URLs
_DISCORD_WEBHOOK_RE = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
)

# OAuth tokens (Google ya29)
_OAUTH_TOKEN_RE = re.compile(
    r"\bya29\.[A-Za-z0-9_-]+\b"
)

# Session cookies / auth tokens
_SESSION_COOKIE_RE = re.compile(
    r"\b(?:session|connect\.sid|auth_token|oauth_token)\s*=\s*[A-Za-z0-9%]{20,}"
)

# SSH public keys
_SSH_PUBKEY_RE = re.compile(
    r"ssh-(?:rsa|ed25519|ecdsa|dsa)\s+AAAA[0-9A-Za-z+/]{4,}[=]{0,3}"
)

# Azure connection strings (shared access keys)
_AZURE_CONNSTR_RE = re.compile(
    r"(?:AccountKey|SharedAccessKey|DefaultKey)\s*=\s*[A-Za-z0-9+/=]{30,}"
)

# Basic auth headers (Base64-encoded credentials)
_BASIC_AUTH_RE = re.compile(
    r"(?:Proxy-)?Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}",
    re.IGNORECASE,
)

# Config credential fields: password / passwd / secret / api_key / apikey
# followed by = or : and a non-empty value.  Uses a restrictive key name
# list and requires 3+ non-space chars in value to avoid FP on
# lone key names or empty/masked values (e.g. "***").
_CRED_FIELD_RE = re.compile(
    r"(?:^|[\n\r;,.])\s*"
    r"(password|passwd|secret|api_key|apikey|auth_token|access_token|refresh_token|private_key|secret_key|api_secret)\s*"
    r"[=:]\s*"
    r"(['\"]?)([^\s'\"]{3,})\2",
    re.IGNORECASE | re.MULTILINE,
)


# PromptSanitizer
# ---------------------------------------------------------------------------


class PromptSanitizer:
    """Detect, replace, and restore sensitive data in prompts and responses.

    Thread-safe per-instance for concurrent use (each instance has its own
    vault scoped to a single request lifecycle).

    Usage::

        sanitizer = PromptSanitizer(config)
        sanitized_messages = sanitizer.sanitize_messages(api_messages)
        # ... send to provider ...
        restored_output = sanitizer.restore_response(model_output)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {
            "enabled": True,
            "pii": True,
            "secrets": True,
            "infrastructure": False,  # OFF by default — hostnames useful for LLM
            "urls": False,
            "restore_responses": True,
            "ttl_seconds": 172800,  # 48 hours
            **(config or {}),
        }

        # Persistent vault — maps placeholder -> metadata dict.
        # Survives across API calls within a session for stable IDs.
        self._vault: Dict[str, Dict[str, Any]] = {}

        # Reverse lookup: original_value -> placeholder (for stable ID dedup)
        self._reverse: Dict[str, str] = {}

        # Process-wide counter (always increments, never resets within session)
        self._counter: int = 0

        # Per-request redaction counts (reset each sanitize_text call)
        self._redaction_counts: Dict[str, int] = {}

        self._init_counter_from_vault()

    @property
    def enabled(self) -> bool:
        return bool(self._config.get("enabled", True))

    @property
    def restore_responses(self) -> bool:
        return bool(self._config.get("restore_responses", True))

    def get_vault(self) -> Dict[str, str]:
        """Return the vault as a simple placeholder -> value dict for restoration."""
        return {k: v["value"] for k, v in self._vault.items()} if self._vault else {}

    def get_redaction_counts(self) -> Dict[str, int]:
        """Return category -> count for the last sanitize_text() call."""
        return dict(self._redaction_counts)

    def get_vault_meta(self) -> Dict[str, Dict[str, float]]:
        """Return placeholder metadata (timestamps only, no values)."""
        return {
            k: {"created_at": v["created_at"], "last_used_at": v["last_used_at"]}
            for k, v in self._vault.items()
        }

    def _purge_expired(self) -> None:
        """Remove vault entries that haven't been used in ``ttl_seconds``."""
        ttl = float(self._config.get("ttl_seconds", 172800))
        if ttl <= 0:
            return  # No expiry
        now = time.time()
        expired = [
            ph
            for ph, meta in self._vault.items()
            if now - meta.get("last_used_at", 0) > ttl
        ]
        for ph in expired:
            value = self._vault[ph]["value"]
            self._reverse.pop(value, None)
            del self._vault[ph]
        if expired:
            logger.info("Sanitizer purged %d expired vault entries", len(expired))

    def _init_counter_from_vault(self) -> None:
        """Seed the counter from the highest ID in the existing vault."""
        max_idx = 0
        for ph in self._vault:
            m = re.match(r"^\[([A-Z_]+)_(\d+)\]$", ph)
            if m:
                idx = int(m.group(2))
                if idx > max_idx:
                    max_idx = idx
        self._counter = max_idx

    def reset(self) -> None:
        """Reset per-request state.  Vault (stable IDs) is NOT cleared."""
        self._redaction_counts.clear()
        # _counter is never reset — reusing a stale ID would break vault consistency

    # ------------------------------------------------------------------
    # Public API: sanitize + restore
    # ------------------------------------------------------------------

    def sanitize_text(self, text: str) -> str:
        """Sanitize a single text string, replacing sensitive data with placeholders.

        Args:
            text: The input string to sanitize.

        Returns:
            Sanitized string with placeholders.
        """
        if not self.enabled or not text:
            return text

        self.reset()
        self._purge_expired()

        text = self._sanitize_secrets(text)
        text = self._sanitize_pii(text)
        text = self._sanitize_infrastructure(text)
        text = self._sanitize_urls(text)

        # Log redaction summary (no original values exposed)
        if self._redaction_counts:
            summary = ", ".join(
                f"{cat}: {cnt}"
                for cat, cnt in sorted(self._redaction_counts.items())
            )
            logger.info(
                "Sanitizer redacted %d items: %s",
                sum(self._redaction_counts.values()),
                summary,
            )

        return text

    def sanitize_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitize an OpenAI-format messages list in-place.

        Walks all string content in the message list (content, tool call
        arguments, name fields, reasoning fields) and replaces sensitive
        data with placeholders stored in the vault.

        Args:
            messages: The api_messages list to sanitize (mutated in-place).

        Returns:
            The same messages list, mutated in-place for efficiency.
        """
        if not self.enabled:
            return messages

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            # Sanitize string content
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = self.sanitize_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        part_text = part.get("text")
                        if isinstance(part_text, str):
                            part["text"] = self.sanitize_text(part_text)
                        # Image captions / custom content blocks
                        for key in ("caption", "name"):
                            val = part.get(key)
                            if isinstance(val, str):
                                part[key] = self.sanitize_text(val)

            # Sanitize tool call arguments (JSON strings)
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if isinstance(tc, dict):
                        fn = tc.get("function")
                        if isinstance(fn, dict):
                            args = fn.get("arguments")
                            if isinstance(args, str):
                                fn["arguments"] = self._sanitize_json_arguments(args)

            # Sanitize name field
            name = msg.get("name")
            if isinstance(name, str):
                msg["name"] = self.sanitize_text(name)

            # Sanitize any other string fields (reasoning, reasoning_content, etc.)
            for key, value in msg.items():
                if key in {"content", "name", "tool_calls", "role"}:
                    continue
                if isinstance(value, str):
                    msg[key] = self.sanitize_text(value)

        return messages

    def restore_text(self, text: str, lock_emoji: bool = False) -> str:
        """Restore original values in a text response.

        Replaces all known placeholders with their original values from
        the vault.

        Args:
            text: The text to restore.
            lock_emoji: If True, appends ``\U0001f512`` (🔒) to each restored value.

        Returns:
            Restored text with original values.
        """
        if not self.restore_responses or not text or not self._vault:
            return text

        vault = self.get_vault()
        # Sort by placeholder length (longest first) to avoid partial
        # replacements where one placeholder is a substring of another.
        placeholders = sorted(vault.keys(), key=len, reverse=True)
        for placeholder in placeholders:
            original = vault[placeholder]
            text = text.replace(
                placeholder, original + ("\U0001f512" if lock_emoji else "")
            )

        return text

    def restore_response(self, response_text: str) -> str:
        """Alias for :meth:`restore_text`."""
        return self.restore_text(response_text)

    # ------------------------------------------------------------------
    # Internal: per-category sanitization helpers
    # ------------------------------------------------------------------

    def _next_placeholder(self, category: str) -> str:
        """Generate the next placeholder for a given category.

        Placeholders are of the form ``[CATEGORY_N]`` where N is a
        process-wide counter starting at 1 (never resets within session).
        """
        self._counter += 1
        return f"[{category.upper()}_{self._counter}]"

    def _sanitize_match(self, match: re.Match, category: str) -> str:
        """Replace a regex match with a stable placeholder.

        If the matched value was already seen in this session, reuses its
        existing placeholder ID.  Otherwise creates a new one.

        Updates redaction counts and usage timestamps.
        """
        original = match.group(0)

        # Never treat safe example values as sensitive
        _SAFE = frozenset({
            "example.com", "example.org", "example.net",
            "test.com", "test.org", "test.net",
            "password", "secret", "changeme",
        })
        if original.lower() in _SAFE:
            return original

        # For EMAIL category: skip if the domain part is a safe domain
        # or subdomain (e.g. anonymous@ftp.example.com)
        if category == "EMAIL" and "@" in original:
            _, domain = original.rsplit("@", 1)
            domain_lower = domain.lower()
            for safe_domain in ("example.com", "example.org", "example.net",
                                "test.com", "test.org", "test.net"):
                if domain_lower == safe_domain or domain_lower.endswith("." + safe_domain):
                    return original

        # Reuse existing placeholder for the same value (stable ID)
        existing = self._reverse.get(original)
        if existing:
            self._vault[existing]["last_used_at"] = time.time()
            self._redaction_counts[category] = (
                self._redaction_counts.get(category, 0) + 1
            )
            return existing

        # Create new placeholder
        self._counter += 1
        placeholder = f"[{category.upper()}_{self._counter}]"
        now = time.time()
        self._vault[placeholder] = {
            "value": original,
            "created_at": now,
            "last_used_at": now,
        }
        self._reverse[original] = placeholder
        self._redaction_counts[category] = (
            self._redaction_counts.get(category, 0) + 1
        )
        return placeholder

    def _sanitize_secrets(self, text: str) -> str:
        """Sanitize secrets: API keys, tokens, private keys, DB URIs."""
        if not self._config.get("secrets", True):
            return text

        # API keys (sk-, ghp_, AIza, etc.)
        if self._has_any_substring(text, [
            "sk-", "sk_", "ghp_", "gho_", "ghs_", "ghu_",
            "github_pat_", "ghr_", "xox", "AIza", "pplx-",
            "fal_", "fc-", "gAAAA", "AKIA", "xai-",
            "SG.", "hf_", "r8_", "npm_", "pypi-", "dop_",
            "doo_", "tvly-", "exa_", "gsk_", "mem0_", "bb_live_",
            "nf_", "ddi", "ddp", "discord_", "sbp_", "ac_",
            "t1", "t2", "pk.", "whsec_", "api-", "sk.", "pat_",
        ]):
            text = _API_KEY_RE.sub(lambda m: self._sanitize_match(m, "API_KEY"), text)

        # JWT tokens
        if "eyJ" in text:
            text = _JWT_RE.sub(lambda m: self._sanitize_match(m, "JWT"), text)

        # Private key blocks (PEM)
        if "BEGIN" in text and "PRIVATE KEY" in text:
            text = _PRIVATE_KEY_RE.sub(lambda m: self._sanitize_match(m, "PRIVATE_KEY"), text)

        # SSH private key blocks (OpenSSH)
        if "BEGIN OPENSSH PRIVATE KEY" in text:
            text = _SSH_KEY_RE.sub(lambda m: self._sanitize_match(m, "SSH_KEY"), text)

        # Database connection strings
        if "://" in text:
            def _db_replace(m):
                protocol_user = m.group(1)
                password = m.group(2)
                at_sign = m.group(3)
                orig = password
                existing = self._reverse.get(orig)
                if existing:
                    self._vault[existing]["last_used_at"] = time.time()
                    self._redaction_counts["DB_CONNSTR"] = self._redaction_counts.get("DB_CONNSTR", 0) + 1
                    return f"{protocol_user}{existing}{at_sign}"
                placeholder = self._next_placeholder("DB_CONNSTR")
                now = time.time()
                self._vault[placeholder] = {
                    "value": orig,
                    "created_at": now,
                    "last_used_at": now,
                }
                self._reverse[orig] = placeholder
                self._redaction_counts["DB_CONNSTR"] = self._redaction_counts.get("DB_CONNSTR", 0) + 1
                return f"{protocol_user}{placeholder}{at_sign}"
            text = _DB_CONNSTR_RE.sub(_db_replace, text)

        # URLs with embedded credentials
        if "://" in text:
            def _url_auth_replace(m):
                orig = m.group(0)
                existing = self._reverse.get(orig)
                if existing:
                    self._vault[existing]["last_used_at"] = time.time()
                    self._redaction_counts["URL_AUTH"] = self._redaction_counts.get("URL_AUTH", 0) + 1
                    return existing
                placeholder = self._next_placeholder("URL_AUTH")
                now = time.time()
                self._vault[placeholder] = {
                    "value": orig,
                    "created_at": now,
                    "last_used_at": now,
                }
                self._reverse[orig] = placeholder
                self._redaction_counts["URL_AUTH"] = self._redaction_counts.get("URL_AUTH", 0) + 1
                return placeholder
            text = _URL_USERINFO_RE.sub(_url_auth_replace, text)

        # ENV assignments: API_KEY=value
        if "=" in text:
            def _env_replace(m):
                name = m.group(1)
                quote = m.group(2) or ""
                value = m.group(3)
                # Skip if the value is already a sanitizer placeholder
                if re.match(r"^\[([A-Z_]+_\d+)\]$", value):
                    return m.group(0)
                placeholder = self._next_placeholder("ENV_SECRET")
                now = time.time()
                self._vault[placeholder] = {
                    "value": value,
                    "created_at": now,
                    "last_used_at": now,
                }
                return f"{name}={quote}{placeholder}{quote}"
            text = _ENV_ASSIGN_RE.sub(_env_replace, text)

        # JSON fields with secret values
        if ":" in text and '"' in text:
            def _json_replace(m):
                key = m.group(1)
                value = m.group(2)
                # Skip if the value is already a sanitizer placeholder
                if re.match(r"^\[([A-Z_]+_\d+)\]$", value):
                    return m.group(0)
                placeholder = self._next_placeholder("JSON_SECRET")
                now = time.time()
                self._vault[placeholder] = {
                    "value": value,
                    "created_at": now,
                    "last_used_at": now,
                }
                return f'{key}: "{placeholder}"'
            text = _JSON_FIELD_RE.sub(_json_replace, text)

        # Config credential fields: password=xxx / secret=yyy / etc.
        if re.search(r"(?:password|passwd|secret|api_key|apikey|auth_token|access_token|refresh_token|private_key|secret_key|api_secret)\s*[=:]", text, re.IGNORECASE):
            def _cred_replace(m):
                key = m.group(1)
                value = m.group(3)
                # Skip already-masked values (***, [FILTERED], [REDACTED], etc.),
                # existing placeholders from earlier sanitization steps
                # ([API_KEY_1], [ENV_SECRET_2], …), and Python/JSON literal
                # non-secrets (None, null, true, false)
                if re.match(r"^(\*{3,}|\[([A-Z_]+_\d+|FILTERED|REDACTED|HIDDEN)\]|\.{3,}|None|null|nil|true|false|undefined|nullptr)$", value, re.IGNORECASE):
                    return m.group(0)
                # Store only the value, replace just the value portion
                # preserving all surrounding formatting (quotes, whitespace)
                existing = self._reverse.get(value)
                if existing:
                    self._vault[existing]["last_used_at"] = time.time()
                    self._redaction_counts["CREDENTIAL"] = self._redaction_counts.get("CREDENTIAL", 0) + 1
                    return (
                        m.group(0)[:m.start(3) - m.start()]
                        + existing
                        + m.group(0)[m.end(3) - m.start():]
                    )
                placeholder = self._next_placeholder("CREDENTIAL")
                now = time.time()
                self._vault[placeholder] = {
                    "value": value,
                    "created_at": now,
                    "last_used_at": now,
                }
                self._reverse[value] = placeholder
                self._redaction_counts["CREDENTIAL"] = self._redaction_counts.get("CREDENTIAL", 0) + 1
                # Reconstruct the match with placeholder in place of value
                return (
                    m.group(0)[:m.start(3) - m.start()]
                    + placeholder
                    + m.group(0)[m.end(3) - m.start():]
                )
            text = _CRED_FIELD_RE.sub(_cred_replace, text)

        # Authorization headers
        if "uthorization" in text or "UTHORIZATION" in text:
            def _auth_replace(m):
                prefix = m.group(1)
                token = m.group(2)
                # Skip if the token is already a sanitizer placeholder
                if re.match(r"^\[([A-Z_]+_\d+)\]$", token):
                    return m.group(0)
                placeholder = self._next_placeholder("AUTH_HEADER")
                now = time.time()
                self._vault[placeholder] = {
                    "value": token,
                    "created_at": now,
                    "last_used_at": now,
                }
                return f"{prefix}{placeholder}"
            text = _AUTH_HEADER_RE.sub(_auth_replace, text)

        # Basic auth headers (Base64-encoded credentials)
        if "Basic " in text and (re.search(r"[Aa]uthorization", text) or "UTHORIZATION" in text):
            text = _BASIC_AUTH_RE.sub(lambda m: self._sanitize_match(m, "BASIC_AUTH"), text)

        # Telegram bot tokens
        if ":" in text:
            def _telegram_replace(m):
                bot_prefix = m.group(1) or ""
                digits = m.group(2)
                token = m.group(3)
                placeholder = self._next_placeholder("TELEGRAM_TOKEN")
                now = time.time()
                self._vault[placeholder] = {
                    "value": token,
                    "created_at": now,
                    "last_used_at": now,
                }
                return f"{bot_prefix}{digits}:{placeholder}"
            text = _TELEGRAM_RE.sub(_telegram_replace, text)

        # Bitcoin addresses (legacy P2PKH/P2SH)
        if "1" in text or "3" in text:
            text = _BITCOIN_ADDR_RE.sub(lambda m: self._sanitize_match(m, "CRYPTO"), text)
        if "bc1" in text:
            text = _BITCOIN_BECH32_RE.sub(lambda m: self._sanitize_match(m, "CRYPTO"), text)

        # Ethereum addresses
        if "0x" in text:
            text = _ETHEREUM_ADDR_RE.sub(lambda m: self._sanitize_match(m, "CRYPTO"), text)

        # OAuth tokens (Google ya29)
        if "ya29" in text:
            text = _OAUTH_TOKEN_RE.sub(lambda m: self._sanitize_match(m, "OAUTH"), text)

        # Session cookies / auth tokens in key=value format
        if "=" in text and ("session" in text or "connect.sid" in text or "auth_token" in text or "oauth_token" in text):
            text = _SESSION_COOKIE_RE.sub(lambda m: self._sanitize_match(m, "SESSION"), text)

        # SSH public keys
        if "AAAA" in text and "ssh-" in text:
            text = _SSH_PUBKEY_RE.sub(lambda m: self._sanitize_match(m, "SSH_PUBKEY"), text)

        # Azure connection strings (shared access keys)
        if "AccountKey" in text or "SharedAccessKey" in text:
            text = _AZURE_CONNSTR_RE.sub(lambda m: self._sanitize_match(m, "AZURE_KEY"), text)

        # Discord webhook URLs
        if "discord" in text and "webhook" in text:
            text = _DISCORD_WEBHOOK_RE.sub(lambda m: self._sanitize_match(m, "DISCORD_WEBHOOK"), text)

        return text

    def _sanitize_pii(self, text: str) -> str:
        """Sanitize PII: emails, phone numbers, SSNs, credit cards."""
        if not self._config.get("pii", True):
            return text

        # Email addresses
        if "@" in text:
            text = _EMAIL_RE.sub(lambda m: self._sanitize_match(m, "EMAIL"), text)

        # Phone numbers
        if "+" in text:
            text = _PHONE_RE.sub(lambda m: self._sanitize_match(m, "PHONE"), text)

        # SSNs (US Social Security Numbers)
        if "-" in text:
            text = _SSN_RE.sub(lambda m: self._sanitize_match(m, "SSN"), text)

        # Credit card numbers (with Luhn check to avoid false positives)
        if any(c.isdigit() for c in text):
            text = _CREDIT_CARD_RE.sub(
                lambda m: self._sanitize_credit_card(m), text
            )

        return text

    def _sanitize_infrastructure(self, text: str) -> str:
        """Sanitize infrastructure: IPs, internal hosts, cloud metadata.

        OFF by default (``infrastructure: false``) since hostnames are
        frequently useful for the LLM to know (e.g. API endpoints, docs
        URLs).  Enable via ``HERMES_SANITIZE_INFRASTRUCTURE=true`` or
        ``security.sanitization.infrastructure: true``.

        Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
        are ALWAYS sanitized regardless of this setting since they are
        never safe to expose.
        """
        if not self._config.get("infrastructure", True):
            return text

        # Private/internal IPs
        text = _PRIVATE_IP_RE.sub(lambda m: self._sanitize_match(m, "IP"), text)

        # Internal hostnames (*.internal, *.local, *.lan, *.corp, *.private)
        text = _INTERNAL_HOST_RE.sub(lambda m: self._sanitize_match(m, "HOST"), text)

        # URLs with embedded credentials (always sensitive)
        if "://" in text:
            text = _URL_USERINFO_RE.sub(lambda m: self._sanitize_match(m, "URL_AUTH"), text)

        # Cloud metadata endpoints
        text = _CLOUD_METADATA_RE.sub(
            lambda m: self._sanitize_match(m, "CLOUD_METADATA"), text
        )

        # AWS ARNs
        if "arn:aws" in text:
            text = _AWS_ARN_RE.sub(lambda m: self._sanitize_match(m, "AWS_ARN"), text)

        return text

    def _sanitize_urls(self, text: str) -> str:
        """Sanitize URLs and domain names (OFF by default, opt-in via config).

        Runs last so internal hosts, IPs, emails, and credentials are
        already handled.  Only catches what wasn't caught by more specific
        patterns above.

        **URL handling** — instead of replacing the entire URL, only the
        hostname (registered domain + TLD) is redacted.  Protocol, path,
        query parameters, and fragment remain visible so the LLM can
        reason about subdomain discovery, API structure, and endpoint
        enumeration.

            Ex: ``https://api.target.com/v1/users?page=1``
            →   ``https://[DOMAIN_1]/v1/users?page=1``

        **Standalone domain handling** — bare FQDNs (3+ labels like
        ``foo.bar.com``) are replaced with ``[DOMAIN_N]`` as before.

        URL regex excludes brackets so URLs containing already-replaced
        placeholders (e.g. ``https://environments.local/path``) are NOT double-caught,
        preventing vault-chaining bugs.
        """
        if not self._config.get("urls", False):
            return text

        if "http" in text.lower():
            from urllib.parse import urlparse

            _SAFE_URL_DOMAINS = frozenset({
                "example.com", "example.org", "example.net",
                "test.com", "test.org", "test.net",
            })

            def _url_hostname_replace(m):
                """Replace only the hostname in a matched URL."""
                url = m.group(0)
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if not hostname:
                        return url

                    # Never treat safe example/test domains as sensitive.
                    # Check if hostname is exactly a safe domain OR ends with one
                    # (e.g. "api.example.com" should also be safe).
                    hostname_lower = hostname.lower()
                    if any(
                        hostname_lower == safe or hostname_lower.endswith("." + safe)
                        for safe in _SAFE_URL_DOMAINS
                    ):
                        # Safe domain (exact or subdomain) — pass through
                        # unchanged. _domain_replace also checks safe domains,
                        # so the second pass won't catch subdomains either.
                        return url

                    # Validate TLD against IANA list — skip redaction if the
                    # TLD isn't a real top-level domain (prevents false
                    # positives on fake/non-existent domains).
                    last_dot = hostname_lower.rfind(".")
                    if last_dot == -1 or not _valid_tld(hostname_lower[last_dot + 1:]):
                        return url

                    # Create or reuse a placeholder for this hostname.
                    # Using the 'DOMAIN' category so standalone domains and
                    # URL hostnames share the same placeholder namespace.
                    key = hostname.lower()
                    existing = self._reverse.get(key)
                    if existing:
                        placeholder = existing
                        self._vault[existing]["last_used_at"] = time.time()
                    else:
                        self._counter += 1
                        placeholder = f"[DOMAIN_{self._counter}]"
                        now = time.time()
                        self._vault[placeholder] = {
                            "value": key,
                            "created_at": now,
                            "last_used_at": now,
                        }
                        self._reverse[key] = placeholder

                    self._redaction_counts["DOMAIN"] = (
                        self._redaction_counts.get("DOMAIN", 0) + 1
                    )

                    # Place the placeholder inside the original netloc,
                    # preserving port, userinfo, and original hostname casing.
                    netloc = parsed.netloc
                    lowered = netloc.lower()
                    idx = lowered.find(hostname)
                    if idx == -1:
                        return url  # edge case — shouldn't happen
                    new_netloc = netloc[:idx] + placeholder + netloc[idx + len(hostname):]

                    # Reconstruct the URL with the replaced netloc.
                    # We rebuild from raw pieces to avoid urlunparse
                    # re-encoding that could mangle the path/query.
                    scheme = parsed.scheme or "https"
                    return f"{scheme}://{new_netloc}{parsed.path or ''}" + (
                        f"?{parsed.query}" if parsed.query else ""
                    ) + (
                        f"#{parsed.fragment}" if parsed.fragment else ""
                    )
                except Exception:
                    return url

            text = _URL_RE.sub(_url_hostname_replace, text)

        if "." in text:
            def _domain_replace(m):
                """Replace a standalone domain match, validating the TLD first."""
                domain = m.group(0)
                domain_lower = domain.lower()

                # Never replace safe examples/test domains (including subdomains)
                _SAFE_DOMAIN_TLDS = ("example.com", "example.org", "example.net",
                                     "test.com", "test.org", "test.net")
                if any(domain_lower == safe or domain_lower.endswith("." + safe)
                       for safe in _SAFE_DOMAIN_TLDS):
                    return domain

                # Validate TLD against IANA list
                last_dot = domain_lower.rfind(".")
                if last_dot != -1 and _valid_tld(domain_lower[last_dot + 1:]):
                    return self._sanitize_match(m, "DOMAIN")
                return domain

            text = _DOMAIN_RE.sub(_domain_replace, text)

        return text

    def _sanitize_json_arguments(self, args: str) -> str:
        """Sanitize tool call arguments that are JSON strings.

        Attempts to parse the JSON, sanitize string values, and re-serialize.
        Falls back to regex-based text sanitization if JSON parsing fails.
        """
        try:
            parsed = json.loads(args)
            sanitized = self._sanitize_json_value(parsed)
            return json.dumps(sanitized, separators=(",", ":"))
        except (json.JSONDecodeError, TypeError, ValueError):
            return self.sanitize_text(args)

    def _sanitize_json_value(self, value: Any) -> Any:
        """Recursively sanitize JSON values."""
        if isinstance(value, str):
            return self.sanitize_text(value)
        elif isinstance(value, dict):
            return {k: self._sanitize_json_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._sanitize_json_value(v) for v in value]
        return value

    def _sanitize_credit_card(self, match: re.Match) -> str:
        """Sanitize a potential credit card number with Luhn validation.

        Only replaces if the number passes the Luhn check, preventing
        false positives on arbitrary digit strings like version numbers
        or timestamps.
        """
        raw = match.group(0)
        digits = re.sub(r"[\s\-]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            return raw
        # Luhn algorithm check
        try:
            check_digits = [int(d) for d in digits]
            for i in range(len(check_digits) - 2, -1, -2):
                check_digits[i] *= 2
                if check_digits[i] > 9:
                    check_digits[i] -= 9
            if sum(check_digits) % 10 != 0:
                return raw
        except (ValueError, IndexError):
            return raw
        return self._sanitize_match(match, "CREDIT_CARD")

    @staticmethod
    def _has_any_substring(text: str, substrings: List[str]) -> bool:
        """Cheap pre-check: return True if any substring appears in text."""
        return any(s in text for s in substrings)

    # ------------------------------------------------------------------
    # Vault merging (for parallel processing)
    # ------------------------------------------------------------------

    @staticmethod
    def merge_vaults(vaults: List[Dict[str, str]]) -> Dict[str, str]:
        """Merge multiple vaults from parallel sanitization runs.

        Later vaults overwrite earlier ones for the same placeholder.
        """
        result: Dict[str, str] = {}
        for v in vaults:
            result.update(v)
        return result


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------


def create_sanitizer_from_config(security_config: Optional[Dict[str, Any]] = None) -> PromptSanitizer:
    """Create a :class:`PromptSanitizer` from a Hermes config ``security`` section.

    Expected config shape::

        security:
          sanitization:
            enabled: true
            pii: true
            secrets: true
            infrastructure: true
            restore_responses: true

    If the config is absent or ``sanitization`` is not present, the
    sanitizer is returned but **disabled** (opt-in by default).
    """
    if not security_config:
        return PromptSanitizer({"enabled": False})

    sanitization_config = security_config.get("sanitization", {})
    if not sanitization_config:
        return PromptSanitizer({"enabled": False})

    return PromptSanitizer(sanitization_config)


__all__ = [
    "PromptSanitizer",
    "create_sanitizer_from_config",
]
