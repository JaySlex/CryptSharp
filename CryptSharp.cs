using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class CryptSharp
{
    /// <summary>
    /// Returns Sha256 hash
    /// </summary>
    /// <param name="rawData">UTF8 String</param>
    /// <returns>HEX string</returns>
    public static byte[] ComputeSha256Hash(string rawData)
    {
        return ComputeSha256Hash(Encoding.UTF8.GetBytes(rawData));
    }

    /// <summary>
    /// Returns Sha256 hash
    /// </summary>
    /// <param name="rawData">bytes</param>
    /// <returns></returns>
    public static byte[] ComputeSha256Hash(byte[] rawData)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            return sha256Hash.ComputeHash(rawData);
        }
    }


    public static byte[] EncryptAES(byte[] data, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB; // ECB mode (No IV)
            aes.Padding = PaddingMode.PKCS7;
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }
    }
    public static byte[] EncryptAES(string data, byte[] key)
    {
        return EncryptAES(Encoding.UTF8.GetBytes(data), key);
    }
    public static byte[] DecryptAES(byte[] cipherText, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.Mode = CipherMode.ECB; // ECB mode (No IV)
            aes.Padding = PaddingMode.PKCS7;
            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return decryptedBytes;
            }
        }
    }


    public static int GenerateSecureRandomNumber(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be less than maxValue");

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            byte[] randomBytes = new byte[4]; // 4 bytes for a 32-bit integer
            rng.GetBytes(randomBytes);

            int randomInt = BitConverter.ToInt32(randomBytes, 0) & int.MaxValue; // Convert to positive int
            return (randomInt % (maxValue - minValue)) + minValue; // Scale to range
        }
    }
    public static byte[] GenerateRandomBytes(int length)
    {
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            byte[] randomBytes = new byte[length];
            rng.GetBytes(randomBytes);
            return randomBytes;
        }
    }

    public static RSAKeyPair GenerateRSAKeyPair(int keySize = 2048)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
        {
            return new RSAKeyPair
            {
                PublicKeyXml = rsa.ToXmlString(false), // Public Key Only
                PrivateKeyXml = rsa.ToXmlString(true)  // Private + Public Key
            };
        }
    }
    public static byte[] EncryptRSA(byte[] data, string publicKeyXml)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(publicKeyXml);
            return rsa.Encrypt(data, true); // Uses OAEP Padding
        }
    }

    public static byte[] EncryptRSA(string data, string publicKeyXml)
    {
        return EncryptRSA(Encoding.UTF8.GetBytes(data), publicKeyXml);
    }

    public static byte[] DecryptRSA(byte[] encryptedData, string privateKeyXml)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(privateKeyXml);
            return rsa.Decrypt(encryptedData, true); // Uses OAEP Padding
        }
    }
}

public struct RSAKeyPair
{
    public string PublicKeyXml;
    public string PrivateKeyXml;
}