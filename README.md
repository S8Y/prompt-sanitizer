# prompt-sanitizer

**Prompt & Response Sanitization Layer for Sensitive Data Protection.**

A Hermes Agent plugin that detects, replaces, and restores sensitive data before
it reaches LLM providers — while preserving full functionality for tool calls,
file operations, and user-facing output.

```
User: "check credentials admin:changeme on scanme.testcorp.com:8080"

  |  sanitize ↓
  ▼
[PROVIDER]  sees: "check credentials [CREDENTIAL_1] on [DOMAIN_74cc65bb_1]"

  |  restore ↑
  ▼
User sees:   "check credentials [CREDENTIAL_1]→admin:changeme🔒 on [DOMAIN_74cc65bb_1]→scanme.testcorp.com🔒:8080"
Tool uses:   real values (auto-restored before dispatch)
```

---

## Features

- **Secrets detection** — 50+ API key patterns (OpenAI, AWS, GitHub, Stripe,
  Slack, Google, Discord, etc.), JWT tokens, PEM/SSH private keys, DB
  connection strings, Telegram bot tokens, OAuth tokens, Azure connection keys
- **PII detection** — emails, phone numbers, SSNs, credit card numbers (Luhn)
- **Credential field detection** — `password=`, `api_key=`, `secret=`,
  `auth_token=`, `access_token=` assignments in any format
- **Infrastructure detection** — private/internal IPs, internal hostnames
  (`*.internal`, `*.local`, `*.corp`), AWS ARNs, cloud metadata endpoints
- **URL/hostname detection** — full URLs and 3+ label domain names
  (**enabled by default in v1.1.0**). Validated against 1437 official IANA TLDs
  — hosts with non-existent TLDs (`.homeassistant`, `.corpnet`, `.notatld`)
  are never redacted, preventing false positives.
- **HMAC-based SLD domain hashing** — same second-level domain across different
  TLDs produces the same hash prefix (e.g. `evilcorp.com` → `[DOMAIN_74cc65bb_1]`,
  `evilcorp.io` → `[DOMAIN_74cc65bb_2]`), making similarity detectable by the LLM
- **Response restoration** — original values restored with `[PLACEHOLDER]→value🔒`
  format in human-facing text, clean bare values in tool call arguments
- **Tool call restoration** — tool call arguments auto-restored before dispatch;
  tools receive real data even when the LLM wrote placeholders
- **Streaming support** — placeholders restored as they arrive in streaming mode
- **LLM awareness** — privacy notice injected into first-turn context explaining
  placeholder system and tool call usage
- **Zero provider exposure** — original values exist only in the local vault,
  never transmitted, logged, or exposed to telemetry
- **False-positive hardened** — JWT regex requires 25+ char header + mandatory
  dots; CRYPTO detection uses targeted pre-scans; ETH address check filters
  hash digests (SHA1:, MD5:, git commit) via context analysis
- **Thread-safe vault** — process-local in-memory mapping with session-stable
  placeholder IDs and 48-hour TTL expiry
- **Graceful degradation** — if sanitization fails, raw prompt passes through;
  agent stays operational

---

## How It Works

The plugin monkey-patches the two API call choke points in
`agent.chat_completion_helpers`:

```
interruptible_api_call(agent, api_kwargs)
interruptible_streaming_api_call(agent, api_kwargs, ...)
```

**Before** the call → `PromptSanitizer.sanitize_messages()` walks every string
field in the message list (content, tool call args, names, reasoning), replaces
matches with stable placeholders like `[EMAIL_24]`, `[API_KEY_3]`, `[DOMAIN_74cc65bb_1]`.

**After** the call → `_restore_response()` puts originals back in the response
content, tool call arguments, and reasoning fields. Tool call arguments get
clean restoration (bare value, no 🔒) to remain valid JSON; human-facing text
uses `[PLACEHOLDER]→value🔒` so the user sees both the placeholder and the
restored value.

**Second pass** → `transform_llm_output` hook catches any stragglers and
ensures markers are applied for display.

**User-facing context** → `pre_llm_call` hook injects a privacy notice on the
first turn so the LLM understands placeholders and how to use them with tools.

### Restoration Format

| Context | Format | Example |
|---------|--------|---------|
| Human text | `[PLACEHOLDER]→value🔒` | `[EMAIL_1]→admin@target.com🔒` |
| Tool call arguments | Bare value | `"admin@target.com"` |

### Placeholder System

Placeholders follow `[CATEGORY_N]` with session-stable IDs. Domain
placeholders use HMAC-based SLD hashing: `[DOMAIN_{8hexchars}_{seq}]`
where the same second-level domain always produces the same 8-char hash
prefix regardless of TLD.

| Category | Format | Detects |
|---|---|---|
| API_KEY | `[API_KEY_N]` | OpenAI, AWS, GitHub, Stripe, Slack... |
| EMAIL | `[EMAIL_N]` | Email addresses |
| PHONE | `[PHONE_N]` | International phone numbers |
| URL | `[URL_N]` | HTTP/HTTPS URLs (enabled by default, domain-only redaction) |
| DOMAIN | `[DOMAIN_{hash}_{N}]` | FQDNs 3+ labels (HMAC-based SLD hash) |
| IP | `[IP_N]` | Private/internal IPs |
| HOST | `[HOST_N]` | *.internal, *.local, *.corp |
| CREDENTIAL | `[CREDENTIAL_N]` | password=, api_key=, secret= |
| JWT | `[JWT_N]` | JWT tokens (25+ char header, mandatory dots) |
| PRIVATE_KEY | `[PRIVATE_KEY_N]` | PEM private key blocks |
| SSH_KEY | `[SSH_KEY_N]` | OpenSSH private keys |
| DB_CONNSTR | `[DB_CONNSTR_N]` | Database connection strings |
| CREDIT_CARD | `[CREDIT_CARD_N]` | Credit card numbers (Luhn) |
| SSN | `[SSN_N]` | US Social Security Numbers |
| AUTH_HEADER | `[AUTH_HEADER_N]` | Authorization: Bearer *** |
| BASIC_AUTH | `[BASIC_AUTH_N]` | Basic auth (Base64) |
| TELEGRAM_TOKEN | `[TELEGRAM_TOKEN_N]` | Telegram bot tokens |
| SESSION | `[SESSION_N]` | Session cookies |
| CRYPTO | `[CRYPTO_N]` | Bitcoin/Ethereum addresses (context-aware) |
| OAUTH | `[OAUTH_N]` | Google OAuth (ya29) tokens |
| AWS_ARN | `[AWS_ARN_N]` | AWS ARNs |
| CLOUD_METADATA | `[CLOUD_METADATA_N]` | Cloud metadata endpoints |
| SSH_PUBKEY | `[SSH_PUBKEY_N]` | SSH public keys |
| AZURE_KEY | `[AZURE_KEY_N]` | Azure shared access keys |
| DISCORD_WEBHOOK | `[DISCORD_WEBHOOK_N]` | Discord webhook URLs |
| ENV_SECRET | `[ENV_SECRET_N]` | Env var secret assignments |
| JSON_SECRET | `[JSON_SECRET_N]` | JSON field secret values |
| URL_AUTH | `[URL_AUTH_N]` | URLs with embedded credentials |

Placeholder IDs are stable within a session — same value gets same ID every
time. A 48-hour TTL purges stale vault entries automatically.

---

## Installation

Enable via the Hermes CLI:

```bash
hermes plugins enable prompt-sanitizer
# or for current session:
hermes plugins load prompt-sanitizer
```

Requires the plugin in a Hermes plugin directory
(`~/.hermes/plugins/prompt-sanitizer/` or project-level `plugins/`).

### Prerequisites

- Hermes Agent 0.1.6+
- Python 3.10+

---

## Configuration

All settings under `security.sanitization` in `config.yaml`:

```yaml
security:
  sanitization:
    enabled: true           # Master toggle
    pii: true               # Emails, phones, SSNs, credit cards
    secrets: true           # API keys, tokens, private keys, credentials
    infrastructure: false   # Private IPs, internal hosts, ARNs (OFF by default)
    urls: true              # URLs and domain names (ON by default in v1.1.0)
    restore_responses: true # Restore placeholders in model responses
```

Environment variable equivalents:

| Variable | Default | Description |
|---|---|---|
| `HERMES_SANITIZE_ENABLED` | `true` | Master toggle |
| `HERMES_SANITIZE_PII` | `true` | PII detection |
| `HERMES_SANITIZE_SECRETS` | `true` | Secrets/tokens/credentials |
| `HERMES_SANITIZE_INFRA` | `false` | Internal infrastructure |
| `HERMES_SANITIZE_URLS` | `true` (was `false` in v1.0.x) | URLs and domain names |
| `HERMES_SANITIZE_RESTORE` | `true` | Response restoration |

### Safe List

Never treated as sensitive:
- `example.com`, `example.org`, `example.net`
- `test.com`, `test.org`, `test.net`
- `password`, `secret`, `changeme`

---

## Usage Scenarios

### General Development

Default settings (`urls: true`, `infrastructure: false`) protect secrets,
PII, and URLs while leaving IPs/hostnames visible for LLM reasoning.

### Red Team / Blue Team (Lockdown Mode)

Enable infrastructure detection for full coverage:

```yaml
security:
  sanitization:
    enabled: true
    infrastructure: true    # also redact IPs/internal hosts
    urls: true              # redact target hosts/URLs
```

With lockdown:
- Target hostnames/URLs → `[DOMAIN_{hash}_{N}]` (HMAC-based SLD hashing;
  same domain across TLDs produces same hash prefix)
- Credentials → `[CREDENTIAL_N]`
- IPs → `[IP_N]`
- LLM sees only placeholders and must use tools to act
- Tool calls receive real values (auto-restored before dispatch)
- User sees restored values with `[PLACEHOLDER]→value🔒` format

**Example red team workflow:**

```
User: "recon scanme.targetcorp.com with creds admin:Passw0rd!"
        ↓ sanitize
LLM sees: "recon [DOMAIN_74cc65bb_1] using creds [CREDENTIAL_2]"
        ↓ reasons: "need to scan [DOMAIN_74cc65bb_1], using curl"
Tool call: curl -u admin:Passw0rd! http://scanme.targetcorp.com/login
        ↓ auto-restored before dispatch
Tool receives: curl -u admin:Passw0rd! http://scanme.targetcorp.com/login
        ↓ response to LLM
User sees: "Scanning [DOMAIN_74cc65bb_1]→scanme.targetcorp.com🔒: 200 OK, login page detected"
```

### Disable

Set `security.sanitization.enabled: false` to bypass entirely.

---

## Architecture

```
  User: "check 127.0.0.1 with admin:changeme"
         |
         ▼
  +-----------------------------+
  | PromptSanitizer              |
  | .sanitize_messages()         |
  | • IP→[IP_24]                 |
  | • creds→[CREDENTIAL_1]       |
  | • stores in thread-safe vault|
  +-----------------------------+
         |
         ▼
  +-----------------------------+
  | LLM Provider                 |
  | Sees only placeholders       |
  | Original values NEVER reach  |
  | provider API/logs            |
  +-----------------------------+
         |
         ▼
  +-----------------------------+
  | _restore_response()          |
  | • content: [X]→value🔒       |
  | • tool args: clean restore   |
  +-----------------------------+
         |
         ▼
  +-----------------------------+
  | Tool Dispatch / User Output  |
  | curl gets real URL           |
  | User sees "[DOMAIN_1]→scanme🔒"|
  +-----------------------------+
```

### Vault

Process-local, thread-safe `Dict[str, Dict]` that is **never**:
- Persisted to disk
- Transmitted over network
- Logged or exposed in telemetry

TTL-based expiry (default 48h) cleans stale entries.

---

## Detected Patterns — Full Reference

### API Keys & Tokens (50+)

| Pattern | Example | Coverage |
|---|---|---|
| OpenAI / OpenRouter | `sk-...` | Generic API keys |
| Anthropic native | `sk-ant-...` | Anthropic API keys |
| GitHub PAT classic | `ghp_...` | Classic tokens |
| GitHub PAT fine-grained | `github_pat_...` | Fine-grained tokens |
| GitHub OAuth/other | `gho_...`, `ghu_...`, `ghs_...`, `ghr_...` | All GitHub token types |
| Slack | `xoxb-...`, `xoxa-...`, `xoxp-...`, `xoxr-...`, `xoxs-...` | All Slack token types |
| Google | `AIza...` | API keys |
| AWS | `AKIA...` | Access key IDs |
| Stripe | `sk_live_...`, `sk_test_...`, `rk_live_...` | Secret & restricted keys |
| SendGrid | `SG....` | API keys |
| HuggingFace | `hf_...` | Tokens |
| Replicate | `r8_...` | API tokens |
| npm / PyPI | `npm_...`, `pypi-...` | Registry tokens |
| DigitalOcean | `dop_v1_...`, `doo_v1_...` | PAT & OAuth |
| Groq | `gsk_...` | Cloud API keys |
| xAI (Grok) | `xai-...` | API keys |
| ElevenLabs | `sk_...` | TTS keys |
| Perplexity | `pplx-...` | API keys |
| Fal.ai | `fal_...` | API keys |
| Firecrawl | `fc-...` | API keys |
| Tavily | `tvly-...` | Search API keys |
| Exa | `exa_...` | Search API keys |
| BrowserBase | `bb_live_...` | API keys |
| Netlify | `nf_...` | Access tokens |
| Datadog | `ddip_...`, `ddp_...` | API & APP keys |
| Discord | `discord_...` | Bot tokens |
| Supabase | `supabase_...` | Service keys |
| Sentry | `sbp_...` | Auth tokens |
| Coinbase | `ac_...` | Access tokens |
| Twilio | `t1...`, `t2...` | Account SIDs |
| Clerk | `sk....` | Secret keys |
| Algolia | `api-...` | API keys |
| Mem0 | `mem0_...` | Platform API keys |
| Generic PAT | `pat_...` | Personal access tokens |
| JWT | `eyJ...` (25+ char header, mandatory dots) | JSON Web Tokens |
| Telegram | `<digits>:<token>` | Bot tokens |
| OAuth (Google) | `ya29....` | OAuth access tokens |

### Credentials & Authentication

- `password=`, `passwd=`, `secret=`, `api_key=`, `apikey=`,
  `auth_token=`, `access_token=`, `refresh_token=`, `private_key=`,
  `secret_key=`, `api_secret=` with non-masked values
- `Authorization: Bearer *** headers
- `Authorization: Basic <base64>` headers
- URLs with embedded credentials: `scheme://user:pass@host`
- Environment variable secret assignments
- JSON field secret values
- Session cookies: `session=xxx`, `connect.sid=xxx`

### PII

- Email addresses
- International phone numbers (`+<country><number>`)
- US SSNs (`XXX-XX-XXXX`)
- Credit card numbers (13-19 digits, Luhn-validated)

### Infrastructure

- Private IPs: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x
- Internal hostnames: `*.internal`, `*.local`, `*.lan`, `*.corp`, `*.private`
- Cloud metadata: 169.254.169.254, metadata.*
- AWS ARNs: `arn:aws:*`, `arn:aws-cn:*`, `arn:aws-us-gov:*`

### Financial & Crypto

- Bitcoin (legacy P2PKH/P2SH, Bech32)
- Ethereum (`0x` + 40 hex chars, context-aware to avoid hash digest FPs)
- Credit cards (Luhn-validated, always-on)

---

## Security Considerations

- **Vault is ephemeral**: process memory only, cleared on session end.
- **HMAC-based domain hashing**: domain placeholders use `[DOMAIN_{hash}_{seq}]`
  where the hash is HMAC-SHA256 with a per-process random key (never persisted).
  Same second-level domain across TLDs produces the same hash prefix, enabling
  the LLM to detect domain similarity without exposing the actual name.
- **URL sanitization on by default** (v1.1.0+): protects target hosts from
  provider logging. Safe-list domains (`example.com`, `test.com`) always pass.
- **TLD-validated URL detection**: only domains with IANA-recognized TLDs are
  redacted. Non-existent TLDs pass through unchanged.
- **JWT false positive prevention**: requires 25+ character header and at least
  one mandatory dot-segment, eliminating FPs on truncated `eyJ` tokens.
- **CRYPTO false positive prevention**: Bitcoin detection uses targeted
  Base58-length pre-scans instead of broad character checks. Ethereum
  detection analyzes surrounding context to avoid flagging hash digests
  (SHA1:, MD5:, git commit).
- **Safe-list domains are protected**: `example.com`, `test.com` and their
  subdomains (`api.test.com`) are never redacted, even inside URLs.
- **Credentials in URLs are always redacted**: `scheme://user:pass@host`
  regardless of URL toggle.
- **Tool call args restored before dispatch**: no tool receives a placeholder.
- **Error resilience**: exceptions in sanitization/restoration fall through
  to the unsanitized path — agent stays operational.

---

## False Positive Prevention

v1.1.0 includes specific hardening against the most common false positive
triggers during red teaming:

| Pattern | Before (v1.0.x) | After (v1.1.0) |
|---------|-----------------|----------------|
| JWT | `eyJ` + 10+ chars, optional dots | `eyJ` + 25+ chars, **mandatory** 1-2 dot-segments (10+ chars each) |
| CRYPTO (BTC) | `if "1" in text or "3" in text: re.sub(...)` (caught ALL text with these digits) | Targeted regex pre-scan: `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b` |
| CRYPTO (ETH) | Same broad check caught `0x` + non-40-hex strings | `0x` + exactly 40 hex chars, with context analysis to skip SHA1:/MD5:/git commit hash digests |
| URL detection | FPs on hosts with fake TLDs | IANA TLD verification — only real TLDs trigger redaction |

---

## Development

### Clone & Test

```bash
git clone <repo-url>
cd plugins/prompt-sanitizer

# Run all test suites (250+ tests)
python3 tests/test_core.py
python3 tests/test_credentials.py
python3 tests/test_error_fp.py
python3 tests/test_restoration.py
python3 tests/test_urls.py
```

### Test Suites

| File | Tests | Covers |
|------|-------|--------|
| `test_core.py` | 77 | All pattern types (email, phone, JWT, crypto, API keys, etc.) |
| `test_error_fp.py` | 79 | Error messages, stack traces, HTTP responses — no FPs |
| `test_credentials.py` | 32 | Basic auth, credential field detection |
| `test_restoration.py` | 25 | Round-trip, tool call args, streaming, lock_emoji format |
| `test_urls.py` | 37 | URL detection, safe domains, TLD validation, SLD hash similarity |
| **Total** | **250** | |

### Project Structure

```
plugins/prompt-sanitizer/
├── __init__.py              # Plugin registration, monkey-patching, hooks
├── plugin.yaml              # Hermes plugin manifest
├── README.md                # This file
├── agent/
│   └── prompt_sanitizer.py  # Core sanitization library
└── tests/
    ├── test_core.py
    ├── test_credentials.py
    ├── test_error_fp.py
    ├── test_restoration.py
    └── test_urls.py
```

### Adding New Patterns

1. Add `re.compile(...)` at module level of `agent/prompt_sanitizer.py`
2. Add a category constant (e.g., `"MY_TYPE"`)
3. Call `text = _MY_RE.sub(lambda m: self._sanitize_match(m, "MY_TYPE"), text)`
   in the appropriate `_sanitize_*` method
4. Add a cheap pre-check (`if "trigger" in text:`) to avoid unnecessary regex
5. Add tests to `tests/`
6. If the pattern might trigger on error messages or code, add false-positive
   tests to `test_error_fp.py`

---

## License

MIT

---

## Changelog

### v1.1.0 (2026-06-06)

**New features:**
- **URL filtering enabled by default** — `HERMES_SANITIZE_URLS=true` (was `false`)
- **HMAC-based SLD domain hashing** — `[DOMAIN_{8hexchars}_{seq}]` format where
  the same second-level domain produces the same hash prefix across TLDs
- **`[PLACEHOLDER]→value🔒` restoration format** — human text shows both
  placeholder and original; tool call arguments get clean bare values

**Bug fixes:**
- **JWT false positive fix** — regex now requires 25+ character header
  (was 10+) and mandatory dot-segments, eliminating FPs on short `eyJ`
  prefixes in code comments, base64 fragments, and log output
- **CRYPTO false positive fix** — replaced broad `if "1" in text or "3" in text`
  pre-check with targeted regex pre-scans for BTC addresses (`\b[13]...{25,34}\b`)
  and ETH addresses (`\b0x[a-fA-F0-9]{40}\b` with context analysis to skip
  SHA1:/MD5:/git commit hash digests)
- **No information leaking** — tool call arguments restored cleanly (no 🔒),
  nested agent dispatch receives restored values; vault is memory-only

**Testing:**
- 250 total tests across 5 suites (was 213)
- `tests/test_urls.py` expanded to 37 tests including SLD hash similarity
- `tests/test_restoration.py` updated for `lock_emoji` restoration format

### v1.0.1 (2026-06-06)

**Bug fixes:**
- **Import resolution**: Fixed `_get_sanitizer()` to use `importlib` fallback when plugin
  directory is not on `sys.path` (fixes `PromptSanitizer class unavailable` warning)
- **Vault value integrity**: `_env_replace`, `_json_replace`, `_auth_replace`,
  `_telegram_replace`, and `_cred_replace` now store only the sensitive value
  (not full context like `OPENAI_API_KEY=...`) in vault — fixing round-trip restoration
- **Placeholder nesting prevention**: ENV, JSON, AUTH, and CRED_FIELD patterns now
  skip values that are already sanitizer placeholders (`[API_KEY_1]`, etc.),
  preventing cascading placeholder chains
- **Safe domain handling**: `_domain_replace` now correctly skips subdomains of
  safe domains (e.g., `ftp.example.com`); URL handler no longer inserts zero-width
  spaces into safe domain URLs
- **Email safe domains**: Emails at safe domains (e.g., `anonymous@example.com`)
  now correctly pass through when `urls=true`

**New:**
- `tests/test_urls.py` — 31 tests covering URL detection, domain-only redaction,
  safe domains, false positives, round-trip restoration, and stable IDs

### v1.0.0

- Initial release

---

## Authors

Nous Research — Hermes Agent team.
