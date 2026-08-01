import sys

def classify_scheme(line: str) -> str:
    safe_kdfs = ['bcrypt', 'argon2', 'scrypt', 'pbkdf2']

    if any(kdf in line for kdf in safe_kdfs):
        return "SAFE"

    if "iter" in line:
        return "SAFE"

    return "VULNERABLE"

for raw in sys.stdin:
    line = raw.strip().lower()
    if not line:
        continue

    result = classify_scheme(line)
    print(result)
