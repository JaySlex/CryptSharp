# CryptSharp

CryptSharp is a lightweight C# cryptographic wrapper that simplifies the usage of common cryptographic functions such as SHA-256 hashing, AES encryption/decryption, RSA key generation and encryption/decryption, and secure random number generation.

## Features
- **SHA-256 Hashing**: Compute SHA-256 hashes from strings or byte arrays.
- **AES Encryption/Decryption**: Encrypt and decrypt data using AES in ECB mode with PKCS7 padding.
- **RSA Encryption/Decryption**: Generate RSA key pairs and perform encryption/decryption using XML-based key representation.
- **Secure Random Number Generation**: Generate cryptographically secure random numbers and byte arrays.

## Installation
Simply include `CryptSharp.cs` in your C# project and start using the cryptographic functions or go in the release and import the dll.

## Usage

### SHA-256 Hashing
```csharp
string data = "Hello World";
byte[] hash = CryptSharp.ComputeSha256Hash(data);
```

### AES Encryption/Decryption
```csharp
byte[] key = CryptSharp.GenerateRandomBytes(32); // AES-256 key
string plainText = "Hello World";
byte[] cipherText = CryptSharp.EncryptAES(plainText, key);
byte[] decryptedText = CryptSharp.DecryptAES(cipherText, key);
string result = Encoding.UTF8.GetString(decryptedText);
```

### RSA Key Generation and Encryption/Decryption
```csharp
RSAKeyPair keys = CryptSharp.GenerateRSAKeyPair();
string publicKey = keys.PublicKeyXml;
string privateKey = keys.PrivateKeyXml;

string message = "Hello RSA";
byte[] encrypted = CryptSharp.EncryptRSA(message, publicKey);
byte[] decrypted = CryptSharp.DecryptRSA(encrypted, privateKey);
string decryptedMessage = Encoding.UTF8.GetString(decrypted);
```

### Secure Random Number Generation
```csharp
int randomNumber = CryptSharp.GenerateSecureRandomNumber(1, 100);
byte[] randomBytes = CryptSharp.GenerateRandomBytes(16);
```

## Security Considerations
- AES encryption is used in ECB mode, which does not provide strong security for large datasets. Consider using CBC mode with an IV for better security. (Will add eventually)
- RSA key sizes are set to 2048 bits for a balance between security and performance.
- Always securely store and manage cryptographic keys.

## License
This project is open-source and provided under the MIT License.

## Author
Developed by JayCode

