# prompt-sanitizer

**Prompt & Response Sanitization Layer for Sensitive Data Protection.**

A Hermes Agent plugin that detects, replaces, and restores sensitive data before
it reaches LLM providers — while preserving full functionality for tool calls,
file operations, and user-facing output.

```
User: "check credentials admin:changeme on scanme.testcorp.com:8080"

  |  sanitize ↓
  ▼
[PROVIDER]  sees: "check credentials [CREDENTIAL_1] on [URL_1]"

  |  restore ↑
  ▼
User sees:   "check credentials admin:changeme🔒 on scanme.testcorp.com🔒:8080"
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
  (opt-in; enable for red/blue team lockdown)
- **Response restoration** — original values restored with 🔒 markers so users
  see what was protected
- **Tool call restoration** — tool call arguments auto-restored before dispatch;
  tools receive real data even when the LLM wrote placeholders
- **Streaming support** — placeholders restored as they arrive in streaming mode
- **LLM awareness** — privacy notice injected into first-turn context explaining
  placeholder system and tool call usage
- **Zero provider exposure** — original values exist only in the local vault,
  never transmitted, logged, or exposed to telemetry
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
matches with stable placeholders like `[EMAIL_24]`, `[API_KEY_3]`, `[URL_2]`.

**After** the call → `_restore_response()` puts originals back in the response
content, tool call arguments, and reasoning fields. Tool call arguments get
clean restoration (no 🔒) to remain valid JSON.

**Second pass** → `transform_llm_output` hook catches any stragglers and
ensures 🔒 markers are applied for display.

**User-facing context** → `pre_llm_call` hook injects a privacy notice on the
first turn so the LLM understands placeholders and how to use them with tools.

### Placeholder System

Placeholders follow `[CATEGORY_N]` with session-stable IDs:

| Category | Format | Detects |
|---|---|---|
| API_KEY | `[API_KEY_N]` | OpenAI, AWS, GitHub, Stripe, Slack... |
| EMAIL | `[EMAIL_N]` | Email addresses |
| PHONE | `[PHONE_N]` | International phone numbers |
| URL | `[URL_N]` | HTTP/HTTPS URLs (opt-in) |
| DOMAIN | `[DOMAIN_N]` | FQDNs 3+ labels (opt-in) |
| IP | `[IP_N]` | Private/internal IPs |
| HOST | `[HOST_N]` | *.internal, *.local, *.corp |
| CREDENTIAL | `[CREDENTIAL_N]` | password=, api_key=, secret= |
| JWT | `[JWT_N]` | JWT tokens |
| PRIVATE_KEY | `[PRIVATE_KEY_N]` | PEM private key blocks |
| SSH_KEY | `[SSH_KEY_N]` | OpenSSH private keys |
| DB_CONNSTR | `[DB_CONNSTR_N]` | Database connection strings |
| CREDIT_CARD | `[CREDIT_CARD_N]` | Credit card numbers (Luhn) |
| SSN | `[SSN_N]` | US Social Security Numbers |
| AUTH_HEADER | `[AUTH_HEADER_N]` | Authorization: Bearer <token> |
| BASIC_AUTH | `[BASIC_AUTH_N]` | Basic auth (Base64) |
| TELEGRAM_TOKEN | `[TELEGRAM_TOKEN_N]` | Telegram bot tokens |
| SESSION | `[SESSION_N]` | Session cookies |
| CRYPTO | `[CRYPTO_N]` | Bitcoin/Ethereum addresses |
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
    infrastructure: true    # Private IPs, internal hosts, ARNs, cloud metadata
    urls: false             # URLs and domain names (opt-in — see below)
    restore_responses: true # Restore placeholders in model responses
```

Environment variable equivalents:

| Variable | Default | Description |
|---|---|---|
| `HERMES_SANITIZE_ENABLED` | `true` | Master toggle |
| `HERMES_SANITIZE_PII` | `true` | PII detection |
| `HERMES_SANITIZE_SECRETS` | `true` | Secrets/tokens/credentials |
| `HERMES_SANITIZE_INFRA` | `true` | Internal infrastructure |
| `HERMES_SANITIZE_URLS` | `false` | URLs and domain names |
| `HERMES_SANITIZE_RESTORE` | `true` | Response restoration |

### Safe List

Never treated as sensitive:
- `example.com`, `example.org`, `example.net`
- `test.com`, `test.org`, `test.net`
- `password`, `secret`, `changeme`

---

## Usage Scenarios

### General Development

Default settings (`urls: false`) protect secrets, PII, and internal
infrastructure while leaving public hostnames visible for LLM reasoning.

### Red Team / Blue Team (Lockdown Mode)

Enable full coverage to prevent target details from reaching the provider:

```yaml
security:
  sanitization:
    enabled: true
    urls: true    # ← critical: redacts target hosts/URLs
```

With lockdown:
- Target hostnames/URLs → `[DOMAIN_N]` / `[URL_N]`
- Credentials → `[CREDENTIAL_N]`
- IPs → `[IP_N]`
- LLM sees only placeholders and must use tools to act
- Tool calls receive real values (auto-restored before dispatch)
- User sees restored values with 🔒 markers

**Example red team workflow:**

```
User: "recon scanme.targetcorp.com with creds admin:Passw0rd!"
        ↓ sanitize
LLM sees: "recon [DOMAIN_1] using creds [CREDENTIAL_2]"
        ↓ reasons: "need to scan [DOMAIN_1], using curl"
Tool call: curl -u admin:Passw0rd! http://scanme.targetcorp.com/login
        ↓ auto-restored before dispatch
Tool receives: curl -u admin:Passw0rd! http://scanme.targetcorp.com/login
        ↓ response to LLM
User sees: "Scanning scanme.targetcorp.com🔒: 200 OK, login page detected"
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
  | • IP→127.0.0.1                 |
  | • creds→[CREDENTIAL_1]      |
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
  | • content: +🔒 markers       |
  | • tool args: clean restore   |
  +-----------------------------+
         |
         ▼
  +-----------------------------+
  | Tool Dispatch / User Output  |
  | curl gets real URL           |
  | User sees "scanning [IP_24]🔒"|
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
| JWT | `eyJ...` | JSON Web Tokens |
| Telegram | `<digits>:<token>` | Bot tokens |
| OAuth (Google) | `ya29....` | OAuth access tokens |

### Credentials & Authentication

- `password=`, `passwd=`, `secret=`, `api_key=`, `apikey=`,
  `auth_token=`, `access_token=`, `refresh_token=`, `private_key=`,
  `secret_key=`, `api_secret=` with non-masked values
- `Authorization: Bearer <token>` headers
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
- Ethereum (`0x` + 40 hex chars)
- Credit cards (Luhn-validated, always-on)

---

## Security Considerations

- **Vault is ephemeral**: process memory only, cleared on session end.
- **Placeholders are counter-based**: incrementing session counters, not
  cryptographic UUIDs. An observer learns nothing about the original value.
- **URL sanitization is opt-in**: protects target hosts from provider logging
  but may cause false positives on legitimate URLs.
- **Credentials in URLs are always redacted**: `scheme://user:pass@host`
  regardless of URL toggle.
- **Tool call args restored before dispatch**: no tool receives a placeholder.
- **Error resilience**: exceptions in sanitization/restoration fall through
  to the unsanitized path — agent stays operational.

---

## Development

### Clone & Test

```bash
git clone <repo-url>
cd plugins/prompt-sanitizer

# Run core tests
python3 -m pytest tests/ -v
```

### Project Structure

```
plugins/prompt-sanitizer/
├── __init__.py      # Plugin registration, monkey-patching, hooks
├── plugin.yaml      # Hermes plugin manifest
├── README.md        # This file
└── tests/           # Test suites
    ├── test_core.py
    ├── test_credentials.py
    ├── test_error_fp.py
    └── test_restoration.py
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

## Authors

Nous Research — Hermes Agent team.
