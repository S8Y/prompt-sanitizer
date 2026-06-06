"""prompt-guard — Hermes plugin for sensitive data protection.

Before messages reach the LLM provider, this plugin detects and replaces
sensitive patterns (API keys, emails, tokens, hostnames, DB URIs, etc.)
with safe placeholders (``[EMAIL_1]``, ``[API_KEY_1]``, …).  After the
provider responds, original values are restored with a ``🔒`` marker so
users can see what was protected.

Activation is handled by the Hermes plugin system — standalone plugins only
load when listed in ``plugins.enabled`` (via ``hermes plugins enable
prompt-guard`` or ``hermes tools → Prompt Guard``).

Configuration is read from ``config.yaml`` ``security.sanitization.*``::

    security:
      sanitization:
        enabled: true
        pii: true
        secrets: true
        infrastructure: true
        restore_responses: true

These are bridged to ``HERMES_SANITIZE_*`` env vars by the config loader.

Architecture
------------
The plugin works by wrapping the low-level API-call functions in
``agent.chat_completion_helpers`` at registration time.  This is the single
choke point through which **all** provider requests and responses flow,
regardless of provider (OpenAI, Anthropic, Gemini, OpenRouter, local models)
or mode (streaming / non-streaming).  No changes to the conversation loop
are required.

Manifest placeholders are stored in a thread-safe per-process vault that is
**never** transmitted, logged, or exposed to telemetry.
"""

from __future__ import annotations

import functools
import logging
import os
import sys
import threading
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state — scoped per-process, never persisted
# ---------------------------------------------------------------------------

# Thread-safe vault: placeholder -> original value.  Mutable mapping that
# is populated during sanitization and consumed during response restoration.
_vault: Dict[str, str] = {}
_vault_lock = threading.Lock()

# Counter for placeholders per category
_counters: Dict[str, int] = {}
_counter_lock = threading.Lock()

# Whether the monkey-patch has been applied (idempotent)
_patch_applied = False
_patch_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _should_sanitize() -> bool:
    """Return True if the sanitization master toggle is on."""
    return os.getenv("HERMES_REDACT_SECRETS", "true").lower() in {
        "1", "true", "yes", "on",
    }


def _read_bool_env(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes", "on"}


def _get_config() -> Dict[str, Any]:
    """Read sanitization config from env vars (bridged from config.yaml)."""
    return {
        "enabled": _should_sanitize(),
        "pii": _read_bool_env("HERMES_SANITIZE_PII", "true"),
        "secrets": _read_bool_env("HERMES_SANITIZE_SECRETS", "true"),
        "infrastructure": _read_bool_env("HERMES_SANITIZE_INFRA", "true"),
        "urls": _read_bool_env("HERMES_SANITIZE_URLS", "true"),
        "restore_responses": _read_bool_env("HERMES_SANITIZE_RESTORE", "true"),
    }


# ---------------------------------------------------------------------------
# Vault management
# ---------------------------------------------------------------------------

def _get_vault() -> Dict[str, str]:
    with _vault_lock:
        return dict(_vault)


def _clear_vault() -> None:
    with _vault_lock:
        _vault.clear()
    with _counter_lock:
        _counters.clear()


def _store_vault(entries: Dict[str, str]) -> None:
    """Merge *entries* into the global vault."""
    with _vault_lock:
        _vault.update(entries)


# ---------------------------------------------------------------------------
# Core sanitization logic
# ---------------------------------------------------------------------------

# We delegate to the PromptSanitizer class from the agent package.
# If for some reason it's unavailable, we define a minimal fallback.

def _get_sanitizer():
    """Import and return the PromptSanitizer class.

    Tries multiple import strategies because the plugin directory may or
    may not be on ``sys.path`` depending on how Hermes loads plugins.
    """
    # Strategy 1: direct import (works when plugin dir is on sys.path)
    try:
        from agent.prompt_sanitizer import PromptSanitizer
        return PromptSanitizer
    except ImportError:
        pass

    # Strategy 2: load via importlib using __file__ to locate the module
    try:
        import importlib.util
        import os

        agent_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "agent", "prompt_sanitizer.py",
        )
        if not os.path.isfile(agent_path):
            raise FileNotFoundError(agent_path)

        spec = importlib.util.spec_from_file_location(
            "prompt_sanitizer_core", agent_path,
        )
        if spec is None or spec.loader is None:
            raise ValueError("Could not create module spec")

        module = importlib.util.module_from_spec(spec)
        sys.modules["prompt_sanitizer_core"] = module
        spec.loader.exec_module(module)
        return module.PromptSanitizer
    except Exception:
        pass

    return None


def _sanitize_messages(messages: List[Dict[str, Any]]) -> Dict[str, str]:
    """Sanitize *messages* in-place and return the placeholder->original vault.

    Returns an empty dict if sanitization is disabled or the sanitizer
    class is unavailable.
    """
    config = _get_config()
    if not config["enabled"]:
        return {}

    SanitizerCls = _get_sanitizer()
    if SanitizerCls is None:
        logger.warning("PromptSanitizer class unavailable — skipping sanitization")
        return {}

    sanitizer = SanitizerCls(config)
    try:
        sanitizer.sanitize_messages(messages)
        vault = sanitizer.get_vault()
        if vault:
            logger.debug(
                "Prompt sanitization applied: %d value(s) redacted",
                len(vault),
            )
        return vault
    except Exception:
        logger.warning("Prompt sanitization failed, proceeding unsanitized", exc_info=True)
        return {}


def _restore_text(text: str, vault: Dict[str, str], lock_emoji: bool = True) -> str:
    """Restore placeholders in *text* using *vault*.

    When *lock_emoji* is True (default for content text), each restored
    value uses ``[PLACEHOLDER]→value🔒`` format so users can see both
    the redacted placeholder and the restored original value.
    Set to False for tool call arguments (must remain valid JSON).
    """
    if not text or not vault:
        return text

    # Sort longest-first to avoid partial-replace issues
    placeholders = sorted(vault.keys(), key=len, reverse=True)
    for ph in placeholders:
        original = vault[ph]
        if lock_emoji:
            text = text.replace(ph, f"{ph}→{original}\U0001f512")
        else:
            text = text.replace(ph, original)
    return text


# ---------------------------------------------------------------------------
# Response restoration
# ---------------------------------------------------------------------------


def _restore_response(response: Any, vault: Dict[str, str]) -> Any:
    """Restore placeholders in an API response object.

    Handles both OpenAI-style ``response.choices[0].message`` and the
    SimpleNamespace response shape produced by the streaming path.
    Returns the (possibly mutated) response.
    """
    if not vault:
        return response

    # Unwrap response — some formats nest the message differently
    choices = getattr(response, "choices", None)
    if not choices:
        return response
    if isinstance(choices, list) and choices:
        choice = choices[0]
    else:
        return response

    msg = getattr(choice, "message", None) or getattr(choice, "delta", None)
    if msg is None:
        return response

    # --- Content ---
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        restored = _restore_text(content, vault, lock_emoji=True)
        if restored != content:
            msg.content = restored

    # --- Tool call arguments (no emoji — must stay valid JSON) ---
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls and isinstance(tool_calls, list):
        for tc in tool_calls:
            if isinstance(tc, SimpleNamespace):
                fn = getattr(tc, "function", None)
                if fn is not None:
                    args_str = getattr(fn, "arguments", None)
                    if isinstance(args_str, str):
                        restored = _restore_text(args_str, vault, lock_emoji=False)
                        if restored != args_str:
                            fn.arguments = restored
            elif isinstance(tc, dict):
                fn = tc.get("function") or tc.get("function", {})
                if isinstance(fn, dict):
                    args_str = fn.get("arguments", "")
                    if isinstance(args_str, str):
                        restored = _restore_text(args_str, vault, lock_emoji=False)
                        if restored != args_str:
                            fn["arguments"] = restored

    # --- Reasoning / thinking content ---
    for field in ("reasoning_content", "reasoning"):
        val = getattr(msg, field, None)
        if isinstance(val, str):
            restored = _restore_text(val, vault, lock_emoji=True)
            if restored != val:
                setattr(msg, field, restored)

    return response


# ---------------------------------------------------------------------------
# Monkey-patching of the API call functions
# ---------------------------------------------------------------------------


def _make_sanitized_wrapper(original_func):
    """Wrap an API call function with pre-call sanitization + post-call restore.

    The wrapper handles both ``interruptible_api_call(agent, api_kwargs)``
    and ``interruptible_streaming_api_call(agent, api_kwargs, ...)``
    signatures.
    """

    @functools.wraps(original_func)
    def wrapper(agent, *args, **kwargs):
        # Extract api_kwargs (first positional arg after `agent`)
        api_kwargs = args[0] if args else {}

        messages = api_kwargs.get("messages", [])
        vault: Dict[str, str] = {}

        # --- Pre-call: sanitize messages in-place ---
        if messages and isinstance(messages, list):
            vault = _sanitize_messages(messages)
            if vault:
                _store_vault(vault)

        # --- Call original ---
        response = original_func(agent, *args, **kwargs)

        # --- Post-call: restore response ---
        if vault and _get_config().get("restore_responses", True):
            try:
                response = _restore_response(response, vault)
            except Exception:
                logger.warning("Response restoration failed", exc_info=True)

        return response

    return wrapper


def _apply_patch() -> None:
    """Apply the monkey-patch to ``agent.chat_completion_helpers``.

    Idempotent — safe to call multiple times.
    """
    global _patch_applied
    with _patch_lock:
        if _patch_applied:
            return

        try:
            import agent.chat_completion_helpers as _helpers
        except ImportError:
            logger.warning(
                "Cannot patch API calls — agent.chat_completion_helpers "
                "not available.  Prompt sanitizer will only apply "
                "transform_llm_output hooks."
            )
            return

        _helpers.interruptible_api_call = _make_sanitized_wrapper(
            _helpers.interruptible_api_call
        )
        _helpers.interruptible_streaming_api_call = _make_sanitized_wrapper(
            _helpers.interruptible_streaming_api_call
        )
        _patch_applied = True
        logger.debug("Prompt sanitizer: patched API call functions")


# ---------------------------------------------------------------------------
# Plugin hooks
# ---------------------------------------------------------------------------


def _on_transform_llm_output(
    response_text: str = "",
    session_id: str = "",
    **kwargs,
) -> Optional[str]:
    """transform_llm_output hook — add 🔒 markers and catch any stragglers.

    The API-call wrapper already restores values in the raw response, but this
    hook fires on the final assembled response text and serves two purposes:

    1. **Belt-and-suspenders**: re-restore any placeholders that may have
       survived the API-level restoration (e.g. from providers with unusual
       response shapes, or from the streaming path where content is
       reassembled after our wrapper).
    2. **🔒 markers**: ensure every restored value carries the lock emoji.
    """
    if not response_text:
        return None

    vault = _get_vault()
    if not vault:
        # No values were sanitized this turn — nothing to restore or mark.
        return None

    restored = _restore_text(response_text, vault, lock_emoji=True)
    if restored == response_text:
        return None  # No change — let the pipeline use the original string
    return restored


def _on_pre_llm_call(
    session_id: str = "",
    user_message: str = "",
    conversation_history: list = None,
    is_first_turn: bool = False,
    **kwargs,
) -> Optional[Dict[str, str]]:
    """Pre_llm_call hook — inject context explaining the placeholder system.

    The LLM sees placeholders like ``[EMAIL_1]``, ``[API_KEY_1]``,
    ``[URL_1]``, ``[DOMAIN_1]`` in prompts but has no way to know they
    represent real values.  This context tells the LLM to treat them as
    the original data, which is essential when the LLM needs to act on
    those values (send an email, fetch a URL, call an API).

    Injection happens on the first turn only to keep token overhead low.
    """
    config = _get_config()
    if not config.get("enabled", False):
        return None

    # Inject only on first turn — the LLM maintains the understanding
    # once it has seen the note.
    if not is_first_turn:
        return None

    return {
        "context": (
            "[PRIVACY NOTICE] A prompt sanitization layer is active in this "
            "session. It replaces sensitive data (API keys, tokens, emails, "
            "phone numbers, URLs, hostnames, credentials, database URIs, "
            "SSNs, credit card numbers, and private IPs) with structured "
            "placeholders like [API_KEY_1], [EMAIL_3], [DOMAIN_a3f8b2c1_7], "
            "[CREDENTIAL_2], [IP_4] before messages reach the provider. "
            "These placeholders are safe to use for reasoning and tool calls.\n\n"
            "PLACEHOLDER FORMAT:\n"
            "- Most placeholders follow [CATEGORY_N] — e.g. [API_KEY_1], "
            "[EMAIL_3], [IP_4]\n"
            "- URL/DOMAIN placeholders include a short hash of the domain "
            "name: [DOMAIN_a3f8b2c1_N]. Placeholders sharing the same hash "
            "prefix (e.g. [DOMAIN_d7e3_1] and [DOMAIN_d7e3_2]) represent "
            "the same registrant on different TLDs — they are likely related "
            "domains.\n"
            "- For URLs: only the registered domain + TLD is replaced with "
            "a [DOMAIN_hash_N] placeholder. Subdomains, path, query, and "
            "fragment remain visible.\n\n"
            "RULES:\n"
            "1. [PLACEHOLDERS ARE THE DATA] — Treat every placeholder as if "
            "the original value is there. [DOMAIN_a3f8b2c1_5] IS the target "
            "hostname. [EMAIL_3] IS the real email address. Reason with "
            "them directly.\n\n"
            "2. [TOOL CALLS] — You CAN use placeholders in tool call "
            "arguments. The system automatically restores original values "
            "before dispatch. The tool receives real data even though you "
            "wrote [DOMAIN_a3f8b2c1_5] or [API_KEY_1] in the argument. "
            "No extra action needed from you.\n\n"
            "3. [🔒 IS DECORATIVE] — After a response is generated, restored "
            "values in displayed text use [PLACEHOLDER]→value🔒 format "
            "so users can see both the redacted form and the original. "
            "This arrow+emoji markup is NEVER present in tool call "
            "arguments, file content, or API calls. It is purely visual "
            "and has no effect on code, tools, or execution.\n\n"
            "4. [FILE WRITES & EXPORTS] — Before writing or uploading any "
            "file that contains placeholders, manually restore them to real "
            "values first. The auto-restore system only covers tool dispatch "
            "and conversation display — it does NOT patch files on disk.\n\n"
            "5. [NEVER GUESS] — Do not attempt to reconstruct, guess, or "
            "reverse-engineer the original value from a placeholder. If you "
            "need the real value for a tool call, just use the placeholder "
            "as-is — the system handles restoration.\n\n"
            "6. [STREAMING] — Placeholders are restored as they arrive in "
            "streaming mode. You will never see a raw [CATEGORY_N] in the "
            "final output."
        )
    }


def _on_session_end(**kwargs) -> None:
    """Clear the sanitization vault when the session ends."""
    _clear_vault()


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """Register the prompt-guard plugin.

    Called once by the Hermes plugin system during startup.
    """
    # 1. Patch API-call functions so messages are sanitized before they
    #    reach any provider and restored after the response arrives.
    _apply_patch()

    # 2. Register the transform hook for the display-text layer.
    ctx.register_hook("transform_llm_output", _on_transform_llm_output)

    # 3. Register the pre-call hook so the LLM is informed about placeholders.
    ctx.register_hook("pre_llm_call", _on_pre_llm_call)

    # 4. On session end, clear the vault to prevent cross-session leakage.
    #    (Covers restart scenarios where the agent object is reused.)
    ctx.register_hook("on_session_end", _on_session_end)
