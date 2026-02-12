using System.Security.Cryptography;

namespace CryptoSoft
{
    public static class Encrypter
    {
        private const int KeySize = 32;
        private const int SaltSize = 32;
        private const int IvSize = 16;
        private const int Iterations = 100_000;

        public static void EncryptFile(string inputFile, string outputFile, string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            using var keyDerivation = new Rfc2898DeriveBytes(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256);

            byte[] key = keyDerivation.GetBytes(KeySize);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.GenerateIV();

            using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
            using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

            fsOutput.Write(salt, 0, salt.Length);

            fsOutput.Write(aes.IV, 0, aes.IV.Length);

            using var cryptoStream = new CryptoStream(
                fsOutput,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            fsInput.CopyTo(cryptoStream);
        }

        public static void DecryptFile(string inputFile, string outputFile, string password)
        {
            using var fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read);

            byte[] salt = new byte[SaltSize];
            fsInput.Read(salt, 0, salt.Length);

            byte[] iv = new byte[IvSize];
            fsInput.Read(iv, 0, iv.Length);

            using var keyDerivation = new Rfc2898DeriveBytes(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256);

            byte[] key = keyDerivation.GetBytes(KeySize);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;

            using var cryptoStream = new CryptoStream(
                fsInput,
                aes.CreateDecryptor(),
                CryptoStreamMode.Read);

            using var fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

            cryptoStream.CopyTo(fsOutput);
        }
    }
}


