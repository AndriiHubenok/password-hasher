import hashlib
import hmac
import sys
import re

seed = 0

def generate_salt(length: int):
    global seed
    salt_bytes = bytearray()
    for _ in range(length):

        seed = (seed * 1103515245 + 12345) % (2**31)
        low_byte = seed & 0xFF
        salt_bytes.append(low_byte)

    return salt_bytes.hex()

def generate_hash(password: str, salt_hex: str, iterations: int, dklen=32):
    password_bytes = password.encode('utf-8')
    salt_bytes = bytes.fromhex(salt_hex)

    block_index = (1).to_bytes(4, byteorder='big')

    u = hmac.new(password_bytes, salt_bytes + block_index, hashlib.sha256).digest()

    t = u

    for _ in range(1, iterations):
        u = hmac.new(password_bytes, u, hashlib.sha256).digest()

        t = bytes(a ^ b for a, b in zip(t, u))

    return t.hex()

def parse_bcrypt_format(line: str):
    args = line[1:].split("$")
    version = args[0]
    cost = args[1]
    salt = args[2][:22]
    h = args[2][22:]

    match = re.search(r"^2[ab]*$", version)
    if not match:
        return "INVALID"

    match = re.search(r"^\d{2}$", cost)
    if not match:
        return "INVALID"

    match = re.search(r"^[./A-Za-z0-9]{22}$", salt)
    if not match:
        return "INVALID"

    match = re.search(r"^[./A-Za-z0-9]{31}$", h)
    if not match:
        return "INVALID"

    return "version={} cost={} salt={} hash={}".format(version, cost, salt, h)

def parse_argon2_format(line: str):
    args = line[7:].split("$")
    variant = args[0]
    v = args[1]
    params = args[2].split(",")
    m = params[0]
    t = params[1]
    p = params[2]

    match = re.search(r"^[id]*$", variant)
    if not match:
        return "INVALID"

    match = re.search(r"^v=\d{2}$", v)
    if not match:
        return "INVALID"

    match = re.search(r"^m=(\d+)$", m)
    if not match:
        return "INVALID"

    match = re.search(r"^t=\d$", t)
    if not match:
        return "INVALID"

    match = re.search(r"^p=\d$", p)
    if not match:
        return "INVALID"

    return "variant={} {} {} {} {}".format(variant, v, m, t, p)

for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not line:
        continue

    if line.startswith("$argon2"):
        print(parse_argon2_format(line))
    else:
        print("INVALID")