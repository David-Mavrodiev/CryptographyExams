using Cyphers.Implementations;
using Cyphers.Implementations.Contracts;
using System;
using static Cyphers.Implementations.Contracts.CaesarCipherKey;

namespace CryptographyExams
{
    class Program
    {
        public static void PerformCaesarCipher()
        {
            string encryptionTarget = "TEXTTOBEENCRYPTED";

            CaesarCipherKey caesarCipherKey = new CaesarCipherKey(CaesarCipherOrientation.RIGHT, 7);
            ICaesarCipher caesarCipher = new CaesarCipher();

            Console.WriteLine($"[Caesar Cipher] Encrypt '{encryptionTarget}'...");

            string encrypted = caesarCipher.Encrypt(encryptionTarget, caesarCipherKey);

            Console.WriteLine($"[Caesar Cipher] Encryption result is '{encrypted}'...");
            Console.WriteLine($"[Caesar Cipher] Decrypt {encrypted}...");

            string decrypted = caesarCipher.Decrypt(encrypted, caesarCipherKey);

            Console.WriteLine($"[Caesar Cipher] Decryption result is {decrypted}...");

            if (decrypted == encryptionTarget)
            {
                Console.WriteLine("[Caesar Cipher] Successful...");
            }
            Console.WriteLine();
        }

        static void Main(string[] args)
        {
            PerformCaesarCipher();
        }
    }
}
