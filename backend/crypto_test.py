from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Step 1: Each party generates a key pair
kelvin_private = X25519PrivateKey.generate()
kelvin_public = kelvin_private.public_key()

mein_private = X25519PrivateKey.generate()
mein_public = mein_private.public_key()

# Step 2: Each party computes the same shared secret
kelvin_shared_secret = kelvin_private.exchange(mein_public)
mein_shared_secret = mein_private.exchange(kelvin_public)

assert kelvin_shared_secret == mein_shared_secret
print("Key exchange successful: both sides agree on the same secret")

# Step 3: Derive an AES key from the shared secret using HKDF
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"encrypted-comm-system"
).derive(kelvin_shared_secret)

# Step 4: Kelvin encrypts a message
aesgcm = AESGCM(derived_key)
nonce = os.urandom(12)  # must be unique per message
plaintext = b"Hello Mein, this message is end-to-end encrypted."
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

print("Ciphertext (what an attacker would see):", ciphertext)

# Step 5: Mein decrypts it using the same derived key
mein_aesgcm = AESGCM(derived_key)
decrypted = mein_aesgcm.decrypt(nonce, ciphertext, None)

print("Decrypted message:", decrypted.decode())