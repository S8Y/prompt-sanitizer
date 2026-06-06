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
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Email addresses
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)

# E.164 phone numbers: +<country><number>, 7-15 digits
_PHONE_RE = re.compile(r"(\+[1-9]\d{6,14})(?![A-Za-z0-9])")

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
    r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END[A-Z ]*PRIVATE KEY-----"
)

# SSH private keys (OpenSSH format)
_SSH_KEY_RE = re.compile(
    r"-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]*?-----END OPENSSH PRIVATE KEY-----"
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
    r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-z0-9_/-]+"
)

# ---------------------------------------------------------------------------
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
            "infrastructure": True,
            "restore_responses": True,
            **(config or {}),
        }
        # Vault: placeholder -> original value
        # Scoped per request, never persisted
        self._vault: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return bool(self._config.get("enabled", True))

    @property
    def restore_responses(self) -> bool:
        return bool(self._config.get("restore_responses", True))

    def get_vault(self) -> Dict[str, str]:
        """Return a copy of the current vault.

        The vault maps placeholders (e.g. ``[API_KEY_1]``) to their
        original values.  It is cleared after each :meth:`reset` call.
        """
        return dict(self._vault)

    def reset(self) -> None:
        """Clear the vault and counters for a new request lifecycle."""
        self._vault.clear()
        self._counters.clear()

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

        text = self._sanitize_secrets(text)
        text = self._sanitize_pii(text)
        text = self._sanitize_infrastructure(text)
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

    def restore_text(self, text: str) -> str:
        """Restore original values in a text response.

        Replaces all known placeholders with their original values from
        the vault.

        Args:
            text: The text to restore.

        Returns:
            Restored text with original values.
        """
        if not self.restore_responses or not text or not self._vault:
            return text

        # Sort by placeholder length (longest first) to avoid partial
        # replacements where one placeholder is a substring of another.
        placeholders = sorted(self._vault.keys(), key=len, reverse=True)
        for placeholder in placeholders:
            original = self._vault[placeholder]
            text = text.replace(placeholder, original)

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
        per-category counter starting at 1.
        """
        self._counters.setdefault(category, 0)
        self._counters[category] += 1
        return f"[{category}_{self._counters[category]}]"

    def _sanitize_match(self, match: re.Match, category: str) -> str:
        """Replace a regex match with a placeholder and store the mapping."""
        original = match.group(0)
        placeholder = self._next_placeholder(category)
        self._vault[placeholder] = original
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
                placeholder = self._next_placeholder("DB_CONNSTR")
                self._vault[placeholder] = password
                return f"{protocol_user}{placeholder}{at_sign}"
            text = _DB_CONNSTR_RE.sub(_db_replace, text)

        # URLs with embedded credentials
        if "://" in text:
            def _url_auth_replace(m):
                placeholder = self._next_placeholder("URL_AUTH")
                self._vault[placeholder] = m.group(0)
                return placeholder
            text = _URL_USERINFO_RE.sub(_url_auth_replace, text)

        # ENV assignments: API_KEY=value
        if "=" in text:
            def _env_replace(m):
                name = m.group(1)
                quote = m.group(2) or ""
                value = m.group(3)
                placeholder = self._next_placeholder("ENV_SECRET")
                self._vault[placeholder] = f"{name}={quote}{value}{quote}"
                return f"{name}={quote}{placeholder}{quote}"
            text = _ENV_ASSIGN_RE.sub(_env_replace, text)

        # JSON fields with secret values
        if ":" in text and '"' in text:
            def _json_replace(m):
                key = m.group(1)
                value = m.group(2)
                placeholder = self._next_placeholder("JSON_SECRET")
                self._vault[placeholder] = f'{key}: "{value}"'
                return f'{key}: "{placeholder}"'
            text = _JSON_FIELD_RE.sub(_json_replace, text)

        # Authorization headers
        if "uthorization" in text or "UTHORIZATION" in text:
            def _auth_replace(m):
                prefix = m.group(1)
                token = m.group(2)
                placeholder = self._next_placeholder("AUTH_HEADER")
                self._vault[placeholder] = f"{prefix}{token}"
                return f"{prefix}{placeholder}"
            text = _AUTH_HEADER_RE.sub(_auth_replace, text)

        # Telegram bot tokens
        if ":" in text:
            def _telegram_replace(m):
                bot_prefix = m.group(1) or ""
                digits = m.group(2)
                token = m.group(3)
                placeholder = self._next_placeholder("TELEGRAM_TOKEN")
                self._vault[placeholder] = f"{bot_prefix}{digits}:{token}"
                return f"{bot_prefix}{digits}:{placeholder}"
            text = _TELEGRAM_RE.sub(_telegram_replace, text)

        return text

    def _sanitize_pii(self, text: str) -> str:
        """Sanitize PII: emails, phone numbers."""
        if not self._config.get("pii", True):
            return text

        # Email addresses
        if "@" in text:
            text = _EMAIL_RE.sub(lambda m: self._sanitize_match(m, "EMAIL"), text)

        # Phone numbers
        if "+" in text:
            text = _PHONE_RE.sub(lambda m: self._sanitize_match(m, "PHONE"), text)

        return text

    def _sanitize_infrastructure(self, text: str) -> str:
        """Sanitize infrastructure: IPs, internal hosts, cloud metadata."""
        if not self._config.get("infrastructure", True):
            return text

        # Private/internal IPs
        text = _PRIVATE_IP_RE.sub(lambda m: self._sanitize_match(m, "IP"), text)

        # Internal hostnames (*.internal, *.local, *.lan, *.corp, *.private)
        text = _INTERNAL_HOST_RE.sub(lambda m: self._sanitize_match(m, "HOST"), text)

        # Cloud metadata endpoints
        text = _CLOUD_METADATA_RE.sub(
            lambda m: self._sanitize_match(m, "CLOUD_METADATA"), text
        )

        # AWS ARNs
        if "arn:aws:" in text:
            text = _AWS_ARN_RE.sub(lambda m: self._sanitize_match(m, "AWS_ARN"), text)

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
