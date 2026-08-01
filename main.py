import sys

# TODO: for each input line describing a password-storage scheme, decide
# whether it is VULNERABLE or SAFE:
#  - Fast, unsalted-or-salted hashes alone (SHA-256, MD5, plain text) are
#    VULNERABLE because they can be brute-forced cheaply.
#  - Purpose-built slow KDFs (bcrypt, argon2/argon2id) are SAFE, even
#    without an explicit salt mentioned (bcrypt salts internally).
#  - A fast hash combined with a large number of iterations (PBKDF2-style,
#    e.g. SHA-256 with 1M iterations) is SAFE.
# Print "VULNERABLE" or "SAFE" for each line.
for raw in sys.stdin:
    line = raw.rstrip("\n").lower()
    if not line: continue
    pass
