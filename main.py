import sys

seed = 0

def generate_salt(length):
    global seed
    salt_bytes = bytearray()
    for _ in range(length):

        seed = (seed * 1103515245 + 12345) % (2**31)
        low_byte = seed & 0xFF
        salt_bytes.append(low_byte)

    return salt_bytes.hex()

for raw in sys.stdin:
    line = raw.rstrip("\n")
    if not line:
        continue

    args = line.split()

    if args[0] == "SEED":
        seed = int(args[1])
    elif args[0] == "SALT":
        print(generate_salt(int(args[1])))