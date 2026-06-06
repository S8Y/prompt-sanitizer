#!/usr/bin/env python3
"""End-to-end restoration verification."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
        print("FAIL [%s] %s" % (label, detail))
        FAIL += 1

def trunc(s, n=80):
    return s if len(s) <= n else s[:n-3] + "..."

print("=" * 60)
print("RESTORATION VERIFICATION")
print("=" * 60)

# --- Test 1: Vault + round-trip ---
print("\n--- Vault + round-trip ---")
s1 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
txt1 = "Card: 4111-1111-1111-1111, SSN: 123-45-6789"
san1 = s1.sanitize_text(txt1)
v1 = s1.get_vault()
rest1 = s1.restore_text(san1)
check("vault non-empty", len(v1) >= 2, "vault: %s" % list(v1.keys()))
check("round-trip", rest1 == txt1, "san=%s rest=%s" % (trunc(san1), trunc(rest1)))

# --- Test 2: Individual round-trips ---
print("\n--- Individual round-trips ---")
for t in [
    "Card: 4111-1111-1111-1111",
    "SSN: 123-45-6789",
    "Phone: +1 (555) 123-4567",
    "Token: ***",
]:
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
    san = s.sanitize_text(t)
    rest = s.restore_text(san)
    check("trip %s" % trunc(t, 35), rest == t,
          "san=%s rest=%s" % (trunc(san), trunc(rest)))

# --- Test 3: Tool-call arg restoration ---
print("\n--- Tool call arg restoration ---")
s3 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s3.sanitize_text("password=hunter2")
v3 = s3.get_vault()
ph = [k for k in v3 if k.startswith("[CREDENTIAL_")][0]
tc = '{"pwd": "' + ph + '", "op": "auth"}'
rest = s3.restore_text(tc)
check("toolcall restored", "hunter2" in rest, "ph=%s rest=%s" % (ph, trunc(rest, 60)))

# --- Test 4: Word-aligned streaming ---
print("\n--- Streaming (word-aligned) ---")
s4 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
orig4 = "SSN: 123-45-6789 and Card: 4111-1111-1111-1111"
san4 = s4.sanitize_text(orig4)
words = san4.split(" ")
restored_words = [s4.restore_text(w) for w in words]
full = " ".join(restored_words)
check("streaming round-trip", full == orig4,
      "orig=%s full=%s" % (trunc(orig4, 60), trunc(full, 60)))

# --- Test 5: Multi-restore from same vault ---
print("\n--- Multi-restore ---")
s5 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s5.sanitize_text("password=hunter2")
v5 = s5.get_vault()
ph5 = [k for k in v5 if k.startswith("[CREDENTIAL_")][0]
r5a = s5.restore_text(ph5)
r5b = s5.restore_text(ph5)
check("restore idempotent", "hunter2" in r5a, "Got: %s" % r5a)
check("second call works", "hunter2" in r5b, "Got: %s" % r5b)

# --- Test 6: Multi-value restore ---
print("\n--- Multi-value ---")
s6 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s6.sanitize_text("Card: 4111-1111-1111-1111 and SSN: 123-45-6789")
v6 = s6.get_vault()
resp6 = ", ".join("val=" + k for k in v6)
rest6 = s6.restore_text(resp6)
check("cc restored", "4111-1111-1111-1111" in rest6, "Got: %s" % rest6)
check("ssn restored", "123-45-6789" in rest6, "Got: %s" % rest6)

# --- Test 7: Instance isolation ---
print("\n--- Instance isolation ---")
s7a = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s7b = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s7a.sanitize_text("password=alpha")
s7b.sanitize_text("password=beta")
va = s7a.get_vault()
vb = s7b.get_vault()
check("vault A has alpha", "alpha" in str(va), "va=%s" % list(va.keys()))
check("vault B has beta", "beta" in str(vb), "vb=%s" % list(vb.keys()))

# --- Test 8: Placeholder format ---
print("\n--- Placeholder format ---")
s8 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s8.sanitize_text("password=secret_value_123")
v8 = s8.get_vault()
for k in v8:
    check("format [CAT_N]", k.startswith("[") and k.endswith("]") and "_" in k,
          "Bad: %s" % k)
    check("has digit", any(c.isdigit() for c in k), "No digit: %s" % k)

# --- Test 9: Long text ---
print("\n--- Long text ---")
s9 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
txt9 = "SSN: 987-65-4321, Card: 4111-1111-1111-1111, Password: p@ssw0rd_s3cr3t"
san9 = s9.sanitize_text(txt9)
v9 = s9.get_vault()
check("long txt ph", len(v9) >= 2, "Only %d: %s" % (len(v9), list(v9.keys())))
rest9 = s9.restore_text(san9)
check("long txt round-trip", rest9 == txt9,
      "orig=%s rest=%s" % (trunc(txt9, 50), trunc(rest9, 50)))

# --- Test 10: Already-masked ---
print("\n--- Already-masked ---")
s10 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s10.sanitize_text("password=***")
v10 = s10.get_vault()
check("masked skipped", len(v10) == 0, "vault: %s" % list(v10.keys()))

# --- Test 11: Empty vault ---
print("\n--- Empty vault ---")
s11 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
r11 = s11.restore_text("Some text here")
check("empty vault safe", r11 == "Some text here", "Got: %s" % r11)

# --- Test 12: No vault matches ---
print("\n--- No vault matches ---")
s12 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
s12.sanitize_text("password=hunter2")
r12 = s12.restore_text("No placeholders here")
check("no ph unchanged", r12 == "No placeholders here", "Got: %s" % r12)

# --- Test 13: Phone ---
print("\n--- Phone ---")
s13 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
txt13 = "Call me at +1 (555) 123-4567"
san13 = s13.sanitize_text(txt13)
rest13 = s13.restore_text(san13)
check("phone round-trip", rest13 == txt13, "rest=%s" % trunc(rest13))

# --- Test 14: Credential field with semicolon ---
print("\n--- Credential field ---")
s14 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
txt14 = "password=hunter2;api_key=sk-abc...mnop"
san14 = s14.sanitize_text(txt14)
v14 = s14.get_vault()
check("cred detected", "hunter2" in str(v14), "vault: %s" % list(v14.keys()))
rest14 = s14.restore_text(san14)
check("cred round-trip", rest14 == txt14, "rest=%s" % trunc(rest14))

# --- Test 15: Mangled email not flagged ---
print("\n--- Mangled email ---")
s15 = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":True})
txt15 = "Contact: admin at example dot com"
san15 = s15.sanitize_text(txt15)
check("mangled not detected", "EMAIL" not in san15, "Got: %s" % trunc(san15))

print()
print("=" * 60)
print("PASS: %d  FAIL: %d  Total: %d" % (PASS, FAIL, PASS+FAIL))
sys.exit(0 if FAIL == 0 else 1)
