from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import sys

# Generate RSA Keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save keys to files
def save_keys(private_key, public_key):
    # Save the private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save the public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Sign the document
def sign_document(private_key, document_path):
    with open(document_path, "rb") as f:
        data = f.read()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("Document signed successfully. Signature saved as 'signature.sig'.")

# Main Function
def main():
    if len(sys.argv) != 2:
        print("Usage: python sign_document.py <document_path>")
        sys.exit(1)
    document_path = sys.argv[1]
    private_key, public_key = generate_keys()
    save_keys(private_key, public_key)
    sign_document(private_key, document_path)

if __name__ == "__main__":
    main()

