import base64
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def atbash_encrypt(text):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr(offset + (25 - (ord(char) - offset)))
        else:
            result += char
    return result

def vigenere_encrypt(text, key='KEY'):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - offset + k) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

def playfair_encrypt(text):
    return "[Playfair encryption not implemented]"

def base64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def fernet_encrypt(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def aes_encrypt(text, key):
    cipher = AES.new(key[:16], AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + ciphertext).decode()

def des_encrypt(text, key):
    cipher = DES.new(key[:8], DES.MODE_ECB)
    padded_text = text + (8 - len(text) % 8) * ' '
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode()

def blowfish_encrypt(text, key):
    cipher = Blowfish.new(key[:16], Blowfish.MODE_ECB)
    padded_text = text + (8 - len(text) % 8) * ' '
    ciphertext = cipher.encrypt(padded_text.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_encrypt(text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(text.encode())
    return base64.b64encode(ciphertext).decode()

# Generate necessary keys
fernet_key = Fernet.generate_key()
aes_key = get_random_bytes(16)
des_key = get_random_bytes(8)
blowfish_key = get_random_bytes(16)
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()

algorithms = {
    "Caesar": lambda text: caesar_encrypt(text),
    "Atbash": lambda text: atbash_encrypt(text),
    "Vigenere": lambda text: vigenere_encrypt(text, 'KEY'),
    "Playfair": lambda text: playfair_encrypt(text),
    "Base64": lambda text: base64_encrypt(text),
    "Fernet": lambda text: fernet_encrypt(text, fernet_key),
    "AES": lambda text: aes_encrypt(text, aes_key),
    "DES": lambda text: des_encrypt(text, des_key),
    "Blowfish": lambda text: blowfish_encrypt(text, blowfish_key),
    "RSA": lambda text: rsa_encrypt(text, rsa_public_key)
}

text = input("Enter the text to encrypt: ")

print("\nAvailable Algorithms:")
for algo in algorithms:
    print(f"- {algo}")
print("- all (to use all algorithms)\n")

choice = input("Enter the algorithm to use (or type 'all'): ")

results = {}
if choice == 'all':
    for name, func in algorithms.items():
        try:
            results[name] = func(text)
        except Exception as e:
            results[name] = f"Error: {str(e)}"
else:
    try:
        results[choice] = algorithms[choice](text)
    except KeyError:
        results[choice] = "Invalid algorithm."

for name, result in results.items():
    print(f"[{name}] => {result}")

write_to_file = input("Do you want to write the results to a file? (yes/no): ").strip().lower()
if write_to_file == 'yes':
    with open("encrypted_output.txt", "w") as f:
        for name, result in results.items():
            f.write(f"[{name}] => {result}\n")
    print("Results written to encrypted_output.txt")
