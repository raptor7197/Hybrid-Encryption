# Hybrid Encryption System

A Python-based encryption system that combines **RSA** and **AES** encryption algorithms to provide secure message encryption. This hybrid approach leverages the strengths of both symmetric (AES) and asymmetric (RSA) encryption.

## 🔐 How It Works

The system uses a **hybrid encryption approach**:

1. **Message Encryption**: Your message is encrypted using AES-256-ECB
2. **Key Protection**: The AES key is encrypted using RSA-2048
3. **Storage**: Both encrypted message and encrypted AES key are saved securely

This approach combines:
- **AES**: Fast symmetric encryption for large messages
- **RSA**: Secure asymmetric encryption for key exchange

## 🚀 Features

- **Hybrid Encryption**: RSA + AES encryption for optimal security and performance
- **Key Management**: Automatic RSA key pair generation and secure storage
- **Multiple Encryption Modes**:
  - Hybrid encryption (RSA + AES)
  - AES-only encryption
  - RSA-only encryption
- **Secure Decryption**: Complete decryption system with error handling
- **File Management**: Encrypted data saved in JSON format
- **User-Friendly Interface**: Interactive command-line interface

## 📋 Requirements

```bash
pip install rsa cryptography
```

### Dependencies
- `rsa`: RSA encryption/decryption
- `cryptography`: AES encryption and cryptographic primitives
- `pickle`: Key serialization
- `json`: Data storage format

## 🛠️ Installation

1. Clone or download the project files
2. Install required dependencies:
   ```bash
   pip install rsa cryptography
   ```
3. Run the encryption system:
   ```bash
   python encrypt.py
   ```

## 📖 Usage

### Encryption (`encrypt.py`)

Run the encryption script:
```bash
python encrypt.py
```

**Available Options:**

1. **Generate new keys and encrypt** - Creates new RSA key pair and encrypts your message
2. **Use existing keys to encrypt** - Uses previously generated keys for encryption
3. **AES-only encryption** - Encrypts using only AES-256
4. **RSA-only encryption** - Encrypts using only RSA (limited message size)
5. **Exit** - Quit the program

### Decryption (`decrypt.py`)

Run the decryption script:
```bash
python decrypt.py
```

**Available Options:**

1. **Decrypt hybrid encrypted message** - Decrypts RSA + AES encrypted data
2. **Decrypt AES-only encrypted message** - Decrypts AES-only data
3. **Decrypt RSA-only encrypted message** - Decrypts RSA-only data
4. **Decrypt custom hybrid data** - Specify custom file paths for decryption
5. **List available encrypted files** - Show all available encrypted files
6. **Exit** - Quit the program

## 📁 File Structure

After running the encryption system, the following files will be created:

```
├── encrypt.py              # Main encryption script
├── decrypt.py              # Main decryption script
├── keys/                   # Directory for RSA keys
│   ├── private_key.pkl     # RSA private key (keep secret!)
│   └── public_key.pkl      # RSA public key
├── encrypted_data.json     # Hybrid encrypted data
├── aes_encrypted.json      # AES-only encrypted data (if used)
└── rsa_encrypted.json      # RSA-only encrypted data (if used)
```

## 🔑 Key Management

### RSA Keys
- **Key Size**: 2048-bit RSA keys
- **Storage**: Keys are saved as pickle files in the `keys/` directory
- **Security**: Keep your private key (`private_key.pkl`) secure and secret

### AES Keys
- **Key Size**: 256-bit AES keys
- **Generation**: Randomly generated for each encryption
- **Protection**: AES keys are encrypted with RSA before storage

## 📄 Data Format

### Hybrid Encrypted Data (`encrypted_data.json`)
```json
{
    "encrypted_message": "hex_encoded_aes_encrypted_message",
    "encrypted_aes_key": "hex_encoded_rsa_encrypted_aes_key",
    "encryption_method": "AES-256-ECB + RSA-2048",
    "timestamp": "encryption_timestamp"
}
```

## 🔒 Security Features

- **RSA-2048**: Industry-standard asymmetric encryption
- **AES-256**: Advanced symmetric encryption
- **PKCS7 Padding**: Proper message padding for AES
- **Secure Key Generation**: Cryptographically secure random key generation
- **Key Separation**: AES keys are never stored in plaintext

## ⚠️ Important Notes

1. **Keep Private Keys Safe**: Never share your private key file
2. **Backup Keys**: Store copies of your keys in a secure location
3. **Message Size Limits**: RSA-only mode has message size limitations
4. **Key Dependencies**: You need the private key to decrypt any encrypted data

## 🎯 Example Workflow

1. **First Time Setup:**
   ```bash
   python encrypt.py
   # Choose option 1 to generate new keys
   # Enter your message
   # Keys and encrypted data are saved
   ```

2. **Decrypt Your Message:**
   ```bash
   python decrypt.py
   # Choose option 1 for hybrid decryption
   # Your original message is recovered
   ```

3. **Subsequent Encryptions:**
   ```bash
   python encrypt.py
   # Choose option 2 to use existing keys
   # Enter new message to encrypt
   ```

## 🛡️ Security Considerations

- This implementation uses ECB mode for AES, which is suitable for demonstration but consider CBC/GCM for production
- Store private keys in secure locations
- Consider implementing additional authentication mechanisms for production use
- Regular key rotation is recommended for high-security applications

## 🤝 Contributing

Feel free to contribute improvements, bug fixes, or additional features to this hybrid encryption system.

## 📜 License

This project is provided as-is for educational and development purposes.
