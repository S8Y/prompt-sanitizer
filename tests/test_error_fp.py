#!/usr/bin/env python3
"""Test sanitizer against common error messages (default settings = urls OFF)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
for key in list(sys.modules.keys()):
    if 'prompt_sanitizer' in key:
        del sys.modules[key]

from agent.prompt_sanitizer import PromptSanitizer

PASS = 0
FAIL = 0

def unchanged(label, text):
    """Verify text is entirely unchanged by default sanitization."""
    global PASS, FAIL
    # Use DEFAULT config (urls=False, infrastructure=False)
    s = PromptSanitizer({"enabled":True,"pii":True,"secrets":True,"infrastructure":False,"urls":False})
    result = s.sanitize_text(text)
    vault = s.get_vault()
    if result != text:
        print(f"  FAIL [{label[:55]}]: output differs")
        print(f"           In bytes: {text.encode('utf-8').hex()[:80]}")
        print(f"           Out: {result!r}")
        print(f"           Vault: {list(vault.keys())}")
        FAIL += 1
    else:
        PASS += 1

print("=" * 60)
print("ERROR MESSAGE FP TEST (default config)")
print("=" * 60)

error_messages = [
    # Python errors
    "Traceback (most recent call last):",
    "  File \"test.py\", line 42, in <module>",
    "ImportError: No module named 'requests'",
    "ValueError: invalid literal for int() with base 10: 'abc'",
    "KeyError: 'username'",
    "KeyError: 'password'",
    "KeyError: 'api_key'",
    "KeyError: 'secret_key'",
    "AttributeError: 'NoneType' object has no attribute 'config'",
    "TypeError: can only concatenate str (not 'int') to str",
    "IndexError: list index out of range",
    "SyntaxError: invalid syntax",
    "NameError: name 'response' is not defined",
    "ZeroDivisionError: division by zero",
    "FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'",
    "Permission denied: '/etc/shadow'",
    "ConnectionError: Connection refused by remote server at https://api.example.com/v1",
    "TimeoutError: The read operation timed out",
    "RuntimeError: Event loop is closed",
    "RecursionError: maximum recursion depth exceeded",

    # Network errors
    "429 Too Many Requests",
    "500 Internal Server Error",
    "502 Bad Gateway: upstream server error",
    "503 Service Unavailable",
    "504 Gateway Timeout",
    "401 Unauthorized: invalid credentials",
    "401 Unauthorized: API key is invalid",
    "403 Forbidden: access denied",
    "404 Not Found: /api/v1/users",
    "error: failed to push some refs to 'https://github.com/user/repo.git'",
    "Host key verification failed.",
    "fatal: Authentication failed for 'https://github.com/user/repo.git'",
    "remote: Invalid username or password.",
    "remote: Password authentication is not supported",
    "fatal: destination path already exists",

    # Package manager / build errors
    "E: Unable to locate package python3-pip",
    "W: Some index files failed to download",
    "npm ERR! code E404",
    "npm ERR! 404 Not Found: package-not-found@1.0.0",
    "ERROR: Could not find a version that satisfies the requirement torch>=2.0",
    "make: *** [Makefile:42: build] Error 1",
    "cc1plus: fatal error: /usr/include/c++/13/iostream: No such file or directory",
    "collect2: error: ld returned 1 exit status",

    # General system messages
    "Segmentation fault (core dumped)",
    "Killed: 9",
    "disk quota exceeded",
    "cannot allocate memory",
    "address already in use",
    "No space left on device",
    "Too many open files",
    "Connection reset by peer",
    "Broken pipe",
    "Operation not permitted",

    # Config values that look sensitive
    "version: 1.2.3",
    "port: 3000",
    "timeout: 30",
    "max_retries: 3",
    "rate_limit: 100",
    "window_size: 1024",

    # API key references in code (not actual keys)
    "config.api_key = None",
    "os.environ.get('API_KEY')",
    "getpass.getpass('Password: ')",
    "logging.debug('Password check: %s', result)",
    "cfg['password']  # not the real value",

    # Error messages mentioning passwords
    "Error: Incorrect password for user admin",
    "Warning: Your password will expire in 7 days",
    "[ERROR] Invalid password format",
    "SSH authentication failed: password method not supported",
    "The password must be at least 8 characters long",
    "Please set the PASSWORD environment variable",
    "Warning: The DB_PASSWORD variable is not set",
    "Could not connect: password authentication failed for user postgres",
    "Login failed: invalid email or password",
    "authentication failed: incorrect username or password",

    # Date/time formats
    "2024-01-01 12:00",
    "date: 2024-12-31",
    "time: 23:59:59",
    "duration: 1:30:00",
    "at: 12:30 PM",
]

print(f"\nTesting {len(error_messages)} error messages...")
for msg in error_messages:
    unchanged(msg[:55], msg)

print()
print("=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed ({PASS+FAIL} total)")
sys.exit(0 if FAIL == 0 else 1)
