import hashlib
import hmac
import sys

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

for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not line:
        continue

    args = line.split()

    if args[0] == "HASH":
        inputs = args[1].split("|")
        print(generate_hash(inputs[0], inputs[1], int(inputs[2])))