#!/usr/bin/env python3
"""Test new credential/basic-auth patterns."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for key in list(sys.modules.keys()):
    if 'prompt_sanitizer' in key:
        del sys.modules[key]

from agent.prompt_sanitizer import PromptSanitizer

PASS = 0
FAIL = 0

def detect(label, text, exp_cat):
    global PASS, FAIL
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
    result = s.sanitize_text(text)
    vault = list(s.get_vault().keys())
    ok = any(k.startswith(exp_cat) for k in vault)
    if ok:
        PASS += 1
    else:
        print(f"  FAIL [{label}]: no [{exp_cat}_ placeholder")
        print(f"           In bytes: {text.encode('utf-8').hex()[:80]}")
        print(f"           Vault: {vault}")
        FAIL += 1

def unchanged(label, text):
    global PASS, FAIL
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
    result = s.sanitize_text(text)
    # Check no CREDENTIAL or BASIC_AUTH placeholders
    vault = list(s.get_vault().keys())
    bad = [k for k in vault if k.startswith('[CREDENTIAL') or k.startswith('[BASIC_AUTH')]
    if bad:
        print(f"  FAIL [{label}]: false positive, vault: {bad}")
        FAIL += 1
    else:
        PASS += 1

print("=" * 60)
print("CREDENTIAL/BASIC_AUTH PATTERN TESTS")
print("=" * 60)

print("\n─── BASIC AUTH ───")
detect("Authorization", 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', '[BASIC_AUTH')
detect("Proxy-Authorization", 'Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', '[BASIC_AUTH')
detect("lowercase auth", 'authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', '[BASIC_AUTH')
detect("all caps", 'AUTHORIZATION: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', '[BASIC_AUTH')

print("\n─── CRED FIELDS ───")
detect("password=", 'password=my_s3cret_pass', '[CREDENTIAL')
detect("api_key =", 'api_key = sk-abc...ef12', '[CREDENTIAL')
detect("secret: quoted", 'secret: "hunter2"', '[CREDENTIAL')
detect("password = quoted", 'password = "correct-horse-battery-staple"', '[CREDENTIAL')
detect("PASSWD=", 'PASSWD=letmein123', '[CREDENTIAL')
detect("auth_token=", 'auth_token=abc123def456', '[CREDENTIAL')
detect("access_token:", 'access_token: abc123def456', '[CREDENTIAL')
detect("refresh_token:", 'refresh_token: xyz789abc', '[CREDENTIAL')
detect("private_key=", 'private_key=some_key_material', '[CREDENTIAL')
detect("secret_key=", 'secret_key=some_secret_value', '[CREDENTIAL')
detect("api_secret:", 'api_secret: some_api_secret', '[CREDENTIAL')
detect("sql comment syntax", '; password=test', '[CREDENTIAL')
detect("newline separated", '\npassword=test123', '[CREDENTIAL')

print("\n─── FALSE POSITIVES ───")
unchanged("masked ***", 'password: ***')
unchanged("masked ****", 'password: ****')
unchanged("masked [FILTERED]", 'password: [FILTERED]')
unchanged("masked [REDACTED]", 'password: [REDACTED]')
unchanged("masked [HIDDEN]", 'password: [HIDDEN]')
unchanged("masked ...", 'password: ...')
unchanged("empty quoted", 'api_key = ""')
unchanged("no value", 'secret:  ')
unchanged("error msg", 'Error: password is incorrect')
unchanged("sentence", 'The password has expired')
unchanged("instruction", 'Please enter your password')
unchanged("key only", 'password:')
unchanged("masked key=value", 'secret = [FILTERED]')
unchanged("masked triple dot", 'api_key = ...')
unchanged("just key mentioned", 'enter your api_key')

# Summary
print()
print("=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed ({PASS+FAIL} total)")
sys.exit(0 if FAIL == 0 else 1)
