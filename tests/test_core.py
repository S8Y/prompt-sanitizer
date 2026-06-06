#!/usr/bin/env python3
"""V2 comprehensive pattern test — avoids safe-list collisions & display redactor."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, '..'))))

# Clear any cached modules
for key in list(sys.modules.keys()):
    if 'prompt_sanitizer' in key:
        del sys.modules[key]

from agent.prompt_sanitizer import PromptSanitizer
import re

PASS = 0
FAIL = 0

def detect(label, text, exp_cat):
    """Check that the text gets a placeholder for the expected category."""
    global PASS, FAIL
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
    result = s.sanitize_text(text)
    vault = s.get_vault()
    # Check vault keys by prefix
    ok = any(k.startswith(f"[{exp_cat}_") for k in vault)
    if ok:
        PASS += 1
    else:
        print(f"  FAIL [{label}]: no [{exp_cat}_ placeholder")
        # Show input bytes to avoid redactor
        print(f"           In bytes: {text.encode('utf-8').hex()[:80]}")
        print(f"           Vault keys: {list(vault.keys())}")
        FAIL += 1

def unchanged(label, text):
    """Verify the text is NOT modified by sanitization."""
    global PASS, FAIL
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
    result = s.sanitize_text(text)
    if result == text:
        PASS += 1
    else:
        print(f"  FAIL [{label}]: false positive")
        print(f"           In bytes: {text.encode('utf-8').hex()[:80]}")
        print(f"           Out bytes: {result.encode('utf-8').hex()[:80]}")
        FAIL += 1

def detect_unchanged(label, text):
    """Same as unchanged — text should remain as-is because it's safe."""
    unchanged(label, text)

# No safe-list collisions — avoid example.com, test.com, etc.
at = chr(64)
dot = chr(46)

print("=" * 60)
print("COMPREHENSIVE PATTERN TEST v2")
print("=" * 60)

# ─── PII ────────────────────────────────────────────────────────────────
print("\n─── EMAIL ───")
detect("basic", f"user{at}mycorp{dot}com", "EMAIL")
detect("subdomain", f"foo{at}bar{dot}myservice{dot}org", "EMAIL")
detect("plus", f"user+tag{at}mail{dot}net", "EMAIL")
unchanged("no at-sign", "this is just plain text")

print("\n─── PHONE ───")
detect("US dashes", "+1-555-123-4567", "PHONE")
detect("US parens", "+1 (555) 123-4567", "PHONE")
detect("UK", "+44 20 7946 0958", "PHONE")
detect("dots", "+1.415.555.0199", "PHONE")
unchanged("version string", "version 2.0.1")

print("\n─── SSN ───")
detect("valid", "123-45-6789", "SSN")
detect("another", "987-65-4321", "SSN")
unchanged("short", "12-34-567")
unchanged("just text", "text-with-dashes")

print("\n─── CREDIT CARD ───")
detect("Visa spaces", "4111 1111 1111 1111", "CREDIT_CARD")
detect("Visa dashes", "4111-1111-1111-1111", "CREDIT_CARD")
detect("Mastercard", "5500 0000 0000 0004", "CREDIT_CARD")
detect("Amex", "3782 822463 10005", "CREDIT_CARD")
detect("Visa no-space", "4111111111111111", "CREDIT_CARD")
unchanged("fails Luhn", "1234567890123456")
unchanged("version", "3.0.1-alpha")

# ─── SECRETS ────────────────────────────────────────────────────────────
print("\n─── API KEYS ───")
# Use proper-length strings for each prefix's requirement
detect("OpenAI sk-", "sk-" + "A" * 30, "API_KEY")
detect("GitHub ghp", "ghp_" + "a" * 40, "API_KEY")
detect("AWS", "AKIAIOSFODNN7EXAMPLE", "API_KEY")
detect("Google AIza", "AIzaSyD-TOKEN-LONG-123456abcdefghijklmnopqrstuvwxyz", "API_KEY")
detect("Slack xoxb", "xoxb-1234567890-1234567890-abcdefghijk", "API_KEY")
detect("HuggingFace", "hf_ABCdef1234567890ghijklmnop", "API_KEY")
detect("Replicate", "r8_ABCdefghijklmnopqrstuvwx", "API_KEY")
detect("Perplexity", "pplx-ABCdef1234567890ghijklmnop", "API_KEY")
detect("Groq", "gsk_ABCdef1234567890ghijklmn", "API_KEY")
detect("SendGrid", "SG.ABCdef1234567890.VWXYZabcde1234567890fghijklmnopqrstuvwxyz", "API_KEY")
detect("Supabase", "sbp_" + "a" * 32, "API_KEY")
detect("Netlify", "nf_" + "a" * 20, "API_KEY")
detect("Discord bot", "discord_" + "A" * 20, "API_KEY")
detect("Stripe live", "sk_live_" + "A" * 20, "API_KEY")
detect("Stripe test", "sk_test_" + "A" * 20, "API_KEY")
detect("Fal", "fal_" + "a" * 20, "API_KEY")
detect("Generic pat", "pat_" + "A" * 20, "API_KEY")
detect("Datadog", "ddi_" + "a" * 20, "API_KEY")

unchanged("not a key", "just a regular sk")

print("\n─── JWT ───")
detect("JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozwog", "JWT")

print("\n─── PRIVATE KEY ───")
detect("RSA", "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY")
detect("EC", "-----BEGIN EC PRIVATE KEY-----\nABCDEF\n-----END EC PRIVATE KEY-----", "PRIVATE_KEY")
detect("OPENSSH", "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n-----END OPENSSH PRIVATE KEY-----", "PRIVATE_KEY")

print("\n─── TELEGRAM ───")
detect("bot token", "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890", "TELEGRAM_TOKEN")

print("\n─── DB CONNSTR ───")
detect("PostgreSQL", "postgresql://user:pass123@localhost:5432/mydb", "DB_CONNSTR")
detect("MongoDB", "mongodb://admin:secretpass@cluster0.mongodb.net:27017/mydb", "DB_CONNSTR")
detect("MySQL", "mysql://app:mypwd@internal.db:3306/app", "DB_CONNSTR")

print("\n─── AUTH HEADER ───")
detect("Bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890", "AUTH_HEADER")

print("\n─── ENV ───")
detect("API_KEY", "OPENAI_API_KEY=" + "A" * 30, "ENV_SECRET")
detect("SECRET", "SECRET_KEY=" + "B" * 20, "ENV_SECRET")
unchanged("DB_HOST", "DB_HOST=localhost")

print("\n─── CRYPTO ───")
detect("Bitcoin P2PKH", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "CRYPTO")
detect("Bitcoin P2SH", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "CRYPTO")
detect("Bitcoin Bech32", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "CRYPTO")
detect("Ethereum", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18", "CRYPTO")
unchanged("not crypto", "just a hex 0x1234")

print("\n─── OAUTH ───")
detect("Google ya29", "ya29.a0AfH6SMC6hB7v8jTqL2mN3pR4sT5uV6wX7yZ8", "OAUTH")

print("\n─── SESSION ───")
detect("session=", "session=abc123def4567890abcdef1234567890abcd", "SESSION")
detect("connect.sid", "connect" + dot + "sid=s%3Aabc123def4567890abcdef1234567890", "SESSION")

print("\n─── SSH PUBKEY ───")
detect("RSA pubkey", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC user@host", "SSH_PUBKEY")
detect("Ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMFVN user@host", "SSH_PUBKEY")

print("\n─── DISCORD WEBHOOK ───")
detect("discord.com", "https://discord.com/api/webhooks/123456789012345678/abcDEFghIJKlmNoA1B2C3D4E5F6G7H8I9J0", "DISCORD_WEBHOOK")
detect("discordapp.com", "https://discordapp.com/api/webhooks/123456789012345678/abcDEFghIJKlmNoA1B2C3D4E5F6G7H8I9J0", "DISCORD_WEBHOOK")

print("\n─── AZURE ───")
detect("AccountKey", "AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "AZURE_KEY")
detect("SharedAccessKey", "SharedAccessKey=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "AZURE_KEY")

print("\n─── AWS ARN ───")
detect("S3 bucket", "arn:aws:s3:::my-bucket", "AWS_ARN")
detect("S3 object", "arn:aws:s3:::my-bucket/path/to/object", "AWS_ARN")
detect("EC2 instance", "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", "AWS_ARN")
detect("Lambda", "arn:aws:lambda:us-east-1:123456789012:function:my-func", "AWS_ARN")
detect("China partition", "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-abc123", "AWS_ARN")

# ─── INFRASTRUCTURE ────────────────────────────────────────────────────
print("\n─── PRIVATE IPs ───")
detect("10.x.x.x", "192.168.1.1 is internal", "IP")
detect("192.168.x.x", "192.168.1.1 is internal", "IP")
unchanged("public IP", "8.8.8.8 is public")
unchanged("web server", "203.0.113.50 is test")

print("\n─── SAFE LIST ───")
unchanged("example.com", "configured at example.com")
unchanged("test.com", "run test.com check")
unchanged("password", "my password is changeme")

# ─── SUMMARY ───────────────────────────────────────────────────────────
print()
print("=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed ({PASS+FAIL} total)")
sys.exit(0 if FAIL == 0 else 1)
