# prompt-sanitizer

A Hermes Agent plugin that detects and replaces sensitive data (API keys, emails, tokens, hostnames, DB URIs, etc.) in prompts before they reach LLM providers, and restores original values in the response with a visible 🔒 lock marker.

```
User Prompt
  → Sanitization Layer (detect & replace)
    → LLM Provider
  → Response Restoration (restore + 🔒)
→ User
```

## Installation

```bash
hermes plugins install nousresearch/prompt-sanitizer
hermes plugins enable prompt-sanitizer
```

Or clone manually:

```bash
git clone https://github.com/nousresearch/prompt-sanitizer.git ~/.hermes/plugins/prompt-sanitizer
hermes plugins enable prompt-sanitizer
```

## How it works

The plugin hooks into the agent's API call functions so every message sent to any LLM provider (OpenAI, Anthropic, Gemini, OpenRouter, local models, streaming or non-streaming) passes through the sanitization layer automatically.

1. **Pre-LLM**: Messages are scanned for sensitive patterns before leaving the local machine
2. **Placeholder replacement**: Detected values are replaced with safe tokens like `[EMAIL_1]`, `[API_KEY_1]`, `[HOST_1]`
3. **In-memory vault**: The placeholder-to-original mapping is stored in a local-only vault that is **never** transmitted, logged, or exposed to telemetry
4. **Post-LLM**: The model response is scanned for placeholders and original values are restored with a 🔒 marker
5. **Session cleanup**: The vault is cleared at session end to prevent cross-session leakage

## What it detects

| Category | Patterns |
|----------|----------|
| **Secrets** | API keys (OpenAI `sk-`, Anthropic `sk-ant-`, Google `AIza`, AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`, Slack `xox*`, 30+ providers), JWT tokens, PEM private keys, SSH keys, DB connection strings, Authorization headers, Telegram bot tokens, env variable assignments (`API_KEY=...`) |
| **PII** | Email addresses, E.164 phone numbers |
| **Infrastructure** | Private/internal IPs (10.x, 172.16-31.x, 192.168.x), internal hostnames (*.internal, *.local, *.lan, *.corp), cloud metadata endpoints, AWS ARNs |

## Configuration

In `~/.hermes/config.yaml`:

```yaml
security:
  sanitization:
    enabled: true       # master toggle
    pii: true           # detect emails, phone numbers
    secrets: true       # detect API keys, tokens, credentials
    infrastructure: true # detect IPs, internal hosts
    restore_responses: true  # replace placeholders in model output
```

Or via environment variables:

```bash
export HERMES_SANITIZE_PII=true
export HERMES_SANITIZE_SECRETS=true
export HERMES_SANITIZE_INFRA=true
export HERMES_SANITIZE_RESTORE=true
```

## Architecture

- **`__init__.py`** — Plugin registration, config helpers, vault management, response restoration, monkey-patch of API call functions, lifecycle hooks
- **`prompt_sanitizer.py`** — Core `PromptSanitizer` class with 40+ regex patterns and per-category sanitization (self-contained, zero external dependencies)

The plugin intercepts at `agent.chat_completion_helpers.interruptible_api_call` and `interruptible_streaming_api_call` — the single choke point through which all provider traffic flows. No changes to the conversation loop or any transport layer are needed.

## Security

- The in-memory vault is **never** written to disk, logs, or telemetry
- Vault is **scoped per-session** and cleared via `on_session_end` hook
- The `transform_llm_output` hook provides a safety-net pass that catches any placeholders surviving the API-level restoration (edge cases from providers with unusual response shapes)
- Tool call arguments are restored **without** the 🔒 marker to keep JSON valid

## License

MIT — see [LICENSE](LICENSE)
