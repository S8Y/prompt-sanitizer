# prompt-guard

**Prompt & Response Sanitization Layer for Sensitive Data Protection.**

A Hermes Agent plugin that detects, replaces, and restores sensitive data
before it reaches LLM providers — while preserving full functionality for
tool calls, file operations, and user-facing output.

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
  (**enabled by default**). Validated against 1437 official IANA TLDs
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
  hash digests (SHA1:, MD5:, git commit) via context analysis; BTC legacy
  check requires at least one base58 letter (all-digit FPs eliminated)
- **Thread-safe vault** — process-local in-memory mapping with session-stable
  placeholder IDs and 48-hour TTL expiry
- **Graceful degradation** — if sanitization fails, raw prompt passes through;
  agent stays operational

---

## Installation

Enable via the Hermes CLI:

```bash
hermes plugins enable prompt-guard
# or for current session:
hermes plugins load prompt-guard
```

Requires the plugin in a Hermes plugin directory
(`~/.hermes/plugins/prompt-guard/` or project-level `plugins/`).

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
    urls: true              # URLs and domain names (ON by default)
    restore_responses: true # Restore placeholders in model responses
```

Environment variable equivalents:

| Variable | Default | Description |
|---|---|---|
| `HERMES_SANITIZE_ENABLED` | `true` | Master toggle |
| `HERMES_SANITIZE_PII` | `true` | PII detection |
| `HERMES_SANITIZE_SECRETS` | `true` | Secrets/tokens/credentials |
| `HERMES_SANITIZE_INFRA` | `false` | Internal infrastructure |
| `HERMES_SANITIZE_URLS` | `true` | URLs and domain names |
| `HERMES_SANITIZE_RESTORE` | `true` | Response restoration |

### Safe List

Never treated as sensitive:

- `example.com`, `example.org`, `example.net`
- `test.com`, `test.org`, `test.net`
- `password`, `secret`, `changeme`

---

## Usage

### General Development

Default settings (`urls: true`, `infrastructure: false`) protect secrets,
PII, and URLs while leaving IPs/hostnames visible for LLM reasoning.

### Red Team / Blue Team (Lockdown Mode)

Enable infrastructure detection for full coverage:

```yaml
security:
  sanitization:
    enabled: true
    infrastructure: true
    urls: true
```

- Target hostnames/URLs → `[DOMAIN_{hash}_{N}]` (HMAC-based SLD hashing;
  same domain across TLDs produces same hash prefix)
- Credentials → `[CREDENTIAL_N]`
- IPs → `[IP_N]`
- LLM sees only placeholders and must use tools to act
- Tool calls receive real values (auto-restored before dispatch)
- User sees restored values with `[PLACEHOLDER]→value🔒` format

### Disable

Set `security.sanitization.enabled: false` to bypass entirely.

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

### Architecture

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

### Restoration Format

| Context | Format | Example |
|---------|--------|---------|
| Human text | `[PLACEHOLDER]→value🔒` | `[EMAIL_1]→admin@target.com🔒` |
| Tool call arguments | Bare value | `"admin@target.com"` |

### Vault

Process-local, thread-safe `Dict[str, Dict]` that is **never**:

- Persisted to disk
- Transmitted over network
- Logged or exposed in telemetry

TTL-based expiry (default 48h) cleans stale entries.

---

## Detected Patterns

### API Keys & Tokens (50+)

| Pattern | Example | Coverage |
|---|---|---|
| OpenAI / OpenRouter | `sk-...` | Generic API keys |
| Anthropic | `sk-ant-...` | Anthropic native |
| GitHub PAT classic | `ghp_...` | Classic tokens |
| GitHub PAT fine-grained | `github_pat_...` | Fine-grained tokens |
| GitHub OAuth/other | `gho_...`, `ghu_...`, `ghs_...`, `ghr_...` | All GitHub types |
| Slack | `xoxb-...`, `xoxa-...`, `xoxp-...`, `xoxr-...`, `xoxs-...` | All Slack types |
| Google | `AIza...` | API keys |
| AWS | `AKIA...` | Access key IDs |
| Stripe | `sk_live_...`, `sk_test_...`, `rk_live_...` | Secret & restricted keys |
| SendGrid | `SG....` | |
| HuggingFace | `hf_...` | |
| Replicate | `r8_...` | |
| npm / PyPI | `npm_...`, `pypi-...` | |
| DigitalOcean | `dop_v1_...`, `doo_v1_...` | |
| Groq | `gsk_...` | |
| xAI (Grok) | `xai-...` | |
| ElevenLabs | `sk_...` | |
| Perplexity | `pplx-...` | |
| Fal.ai | `fal_...` | |
| Firecrawl | `fc-...` | |
| Tavily | `tvly-...` | |
| Exa | `exa_...` | |
| BrowserBase | `bb_live_...` | |
| Netlify | `nf_...` | |
| Datadog | `ddip_...`, `ddp_...` | |
| Discord | `discord_...` | Bot tokens |
| Supabase | `supabase_...` | |
| Sentry | `sbp_...` | |
| Coinbase | `ac_...` | |
| Twilio | `t1...`, `t2...` | Account SIDs |
| Clerk | `sk....` | |
| Algolia | `api-...` | |
| Mem0 | `mem0_...` | |
| Generic PAT | `pat_...` | |
| JWT | `eyJ...` (25+ char header, mandatory dots) | |
| Telegram | `<digits>:<token>` | |
| OAuth (Google) | `ya29....` | |

### Credentials & Authentication

- `password=`, `passwd=`, `secret=`, `api_key=`, `apikey=`,
  `auth_token=`, `access_token=`, `refresh_token=`, `private_key=`,
  `secret_key=`, `api_secret=` with non-masked values
- `Authorization: Bearer ***` headers
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

- Bitcoin legacy (P2PKH/P2SH, Bech32) — requires at least one base58 letter
- Ethereum (`0x` + 40 hex chars, context-aware to avoid hash digests)
- Credit cards (Luhn-validated, always-on)
- Discord webhook URLs

---

## False Positive Prevention

Thoroughly tested against real-world error messages, stack traces, log
output, and natural language to minimise false triggers:

| Pattern | Prevention |
|---------|-----------|
| JWT | `eyJ` + 25+ char header, **mandatory** 1-2 dot-segments |
| BTC legacy | Lookahead requires ≥1 base58 letter — all-digit `1111...` pass through |
| BTC Bech32 | 39+ char minimum — short fragments pass through |
| ETH | Context analysis skips SHA1:/MD5:/git commit hash digests |
| Discord webhook | Exact match on `/api/webhooks/<digits>/<token>` — bare domains pass |
| URL | IANA TLD verification — fake TLDs (`.homeassistant`, `.corp`) pass |
| CRED_FIELD | Skips masked values (***, None, null, true, false, short values) |

---

## Development

### Test

```bash
# Run all 250+ tests
python3 tests/test_core.py
python3 tests/test_credentials.py
python3 tests/test_error_fp.py
python3 tests/test_restoration.py
python3 tests/test_urls.py
```

### Project Structure

```
prompt-guard/
├── __init__.py              # Plugin registration, hooks
├── plugin.yaml              # Hermes plugin manifest
├── README.md
├── after-install.md         # Post-install welcome
├── LICENSE
├── agent/
│   └── prompt_sanitizer.py  # Core sanitization library
└── tests/
    ├── __init__.py
    ├── test_core.py          # 77 pattern tests
    ├── test_credentials.py   # 32 credential tests
    ├── test_error_fp.py      # 79 error-message FP tests
    ├── test_restoration.py   # 25 round-trip tests
    └── test_urls.py          # 37 URL/SLD hash tests
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

## Security

- **Vault is ephemeral**: process memory only, cleared on session end.
- **HMAC-based domain hashing**: domain placeholders use `[DOMAIN_{hash}_{seq}]`
  where the hash is HMAC-SHA256 with a per-process random key (never persisted).
  Same SLD across TLDs → same hash prefix. Non-reversible.
- **URL sanitization on by default**: protects target hosts from provider
  logging. Safe-list domains (`example.com`, `test.com`) always pass.
- **TLD-validated URL detection**: only domains with IANA-recognized TLDs are
  redacted. Non-existent TLDs pass through unchanged.
- **Credentials in URLs are always redacted**: `scheme://user:pass@host`
  regardless of URL toggle.
- **Tool call args restored before dispatch**: no tool receives a placeholder.
- **Error resilience**: exceptions fall through to the unsanitized path.

---

## Changelog

### v1.1.0 (2026-06-06)

**New:**
- URL filtering **enabled by default** (`HERMES_SANITIZE_URLS=true`)
- HMAC-based SLD domain hashing — `[DOMAIN_{hash}_{seq}]` format
- `[PLACEHOLDER]→value🔒` restoration format (human text) with clean
  bare-value restoration for tool call arguments

**False positive fixes:**
- **JWT**: 25+ char header and mandatory dot-segments (was optional dots)
- **CRYPTO (BTC)**: replaced broad `if "1" in text or "3" in text` with
  targeted regex; all-digit FPs eliminated by base58 letter requirement
- **CRYPTO (ETH)**: context analysis skips SHA1:/MD5:/git commit hashes
- **No information leaking**: tool args restored cleanly, no 🔒 in JSON

**Testing:**
- 250 total tests across 5 suites (was 213)
- test_urls.py: expanded to 37 tests incl. SLD hash similarity
- test_restoration.py: updated for `lock_emoji` format

### v1.0.1 (2026-06-06)

**Bug fixes:**
- Import resolution: `_get_sanitizer()` fallback when plugin dir not on sys.path
- Vault value integrity: all value extractors store only the sensitive value
- Placeholder nesting prevention: ENV/JSON/AUTH/CRED patterns skip existing
  placeholders
- Safe domain handling: subdomains of safe domains pass through correctly
- Email safe domains: emails at safe domains pass through when `urls=true`

**New:** tests/test_urls.py (31 tests)

### v1.0.0

- Initial release

---

## License

MIT
