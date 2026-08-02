import hashlib
import hmac
import sys
import re

seed = 0
cost = 0
users = {}

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

def check_rehash(line: str):
    global cost
    current_cost = int(line[1:].split("$")[1])

    if cost > current_cost:
        return True

    return False


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

def compare(a, b):
    if len(a) != len(b): return False
    result = 0

    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def register_user(username: str, password: str):
    global users
    if username in users:
        return False

    users[username] = "bcrypt$" + password
    return True

def login(username: str, password: str):
    global users
    if username in users:
        hashed_password = "bcrypt$" + password
        return compare(users[username], hashed_password)

    return False

def change_password(username: str, old_password: str, new_password: str):
    global users
    is_valid = login(username, old_password)

    if is_valid:
        users[username] = "bcrypt$" + new_password
        return True

    return False

def list_users():
    global users

    if not users:
        print("EMPTY")
        return

    result = ""
    for user in users.keys():
        result += user + ","

    print(result[:-1])

for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not line:
        continue

    if line.startswith("REGISTER"):
        args = line[9:].split()
        result = register_user(args[0], args[1])

        if result:
            print("OK")
        else:
            print("EXISTS")

    elif line.startswith("LOGIN"):
        args = line[6:].split()
        result = login(args[0], args[1])

        if result:
            print("OK")
        else:
            print("BAD")

    elif line.startswith("CHANGE"):
        args = line[7:].split()
        result = change_password(args[0], args[1], args[2])

        if result:
            print("OK")
        else:
            print("BAD")

    elif line.startswith("LIST"):
        list_users()