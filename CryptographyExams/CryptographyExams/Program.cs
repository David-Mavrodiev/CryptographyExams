using Cryptosystems.Implementations;
using Cryptosystems.Implementations.Contracts;
using Cyphers.Implementations;
using Cyphers.Implementations.Contracts;
using System;
using System.Numerics;
using static Cyphers.Implementations.Contracts.CaesarCipherKey;

namespace CryptographyExams
{
    public class Program
    {
        /**
         * Tests the Ceaser cipher implementation.
         */
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

        /**
         * Tests the Vijiner cipher implementation.
         */
        public static void PerformVijinerCipher()
        {
            string encryptionTarget = "ATTACKATDAWN";
            string key = "LEMON";

            IVijinerCipher vijinerCipher = new VijinerCipher();

            Console.WriteLine($"[Vijiner Cipher] Encrypt '{encryptionTarget}'...");

            string encrypted = vijinerCipher.Encrypt(encryptionTarget, key);

            Console.WriteLine($"[Vijiner Cipher] Encryption result is '{encrypted}'...");
            Console.WriteLine($"[Vijiner Cipher] Decrypt {encrypted}...");

            string decrypted = vijinerCipher.Decrypt(encrypted, key);

            Console.WriteLine($"[Vijiner Cipher] Decryption result is {decrypted}...");

            if (decrypted == encryptionTarget)
            {
                Console.WriteLine("[Vijiner Cipher] Successful...");
            }
            Console.WriteLine();
        }

        public static void PerformElGamalCryptosystem()
        {
            IElGamalCryptoSystem elGamalCryptoSystem = new ElGamalCryptoSystem();

            Console.WriteLine("[ElGamal] Generate public/private keys, Alpha and P...");

            Tuple<ElGamalPublicKey, BigInteger> keys = elGamalCryptoSystem.GenerateKeys();
            ElGamalPublicKey pubKey = keys.Item1;
            BigInteger privKey = keys.Item2;

            Console.WriteLine($"[ElGamal] Public key: Kpub = '{pubKey.Kpub}', Alpha = '{pubKey.Alpha}', P = '{pubKey.P}'...");
            Console.WriteLine($"[ElGamal] Private key: d = '{privKey}'...");

            string textToEncrypt = "MementoMori";

            Console.WriteLine($"[ElGamal] Encrypt '{textToEncrypt}'...");

            Tuple<ElGamalEphemeralKey, string> encryptionResult = elGamalCryptoSystem.Encrypt(textToEncrypt, pubKey);
            ElGamalEphemeralKey sessionKey = encryptionResult.Item1;
            string encryptedText = encryptionResult.Item2;

            Console.WriteLine($"[ElGamal] Encrypted text '{encryptedText}'...");
            Console.WriteLine($"[ElGamal] Ke (session key): '{sessionKey.Ke}'...");

            string decryptedText = elGamalCryptoSystem.Decrypt(encryptedText, sessionKey, pubKey, privKey);
            Console.WriteLine($"[ElGamal] Decrypted text: '{decryptedText}'...");

            if (textToEncrypt == decryptedText)
            {
                Console.WriteLine($"[ElGamal] Successful...");
            }
        }

        static void Main(string[] args)
        {
            PerformCaesarCipher();
            PerformVijinerCipher();
            PerformElGamalCryptosystem();

            // TODO Add Diffie-Hellman key exchange
        }
    }
}
