# prompt-sanitizer — installed

The prompt sanitization layer is now active.

## What's protected

When the plugin is enabled, the following sensitive data is automatically detected and replaced with placeholders **before** any message reaches an LLM provider:

- **30+ API key formats** — OpenAI, Anthropic, Google, AWS, GitHub, Stripe, Slack, and more
- **Private keys** — PEM and OpenSSH format
- **JWT tokens**
- **Database connection strings** — postgres://, mysql://, mongodb://, redis://, amqp://
- **Email addresses & phone numbers**
- **Internal hostnames & private IPs** — *.internal, *.local, 10.x, 192.168.x, etc.
- **Cloud metadata endpoints** — 169.254.169.254, etc.
- **Authorization headers & env variable assignments**
- **Telegram bot tokens**

Placeholders are restored in the model's response with a `🔒` marker so you can see what was protected.

## Configuration

To configure categories or disable specific detection, edit `~/.hermes/config.yaml`:

```yaml
security:
  sanitization:
    enabled: true
    pii: true
    secrets: true
    infrastructure: true
    restore_responses: true
```

Then restart Hermes.

## Confirm it's active

```bash
hermes plugins list | grep prompt-sanitizer
```

You should see it listed as **enabled**.

## Uninstall

```bash
hermes plugins disable prompt-sanitizer
hermes plugins remove prompt-sanitizer
```
