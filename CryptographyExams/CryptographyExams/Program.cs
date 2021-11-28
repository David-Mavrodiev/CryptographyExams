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

        private static void PerformDiffieHellmanCryptoSystem()
        {
            Console.WriteLine("[Diffie-Hellman] Generate prime cyclic group...");

            // This is the group info which is publicly known.
            DiffieHellmanCyclicPrimeGroupInfo groupInfo =
                DiffieHellmanCryptoSystem.GenerateCyclicPrimeGroupInfo();

            Console.WriteLine($"[Diffie-Hellman] P = {groupInfo.P}, Alpha = {groupInfo.Alpha}...");

            Console.WriteLine("[Diffie-Hellman] Run simple simulation of Alice and Bob communicating...");
            Console.WriteLine();

            // Create two parties which want to communicate "securely" using Diffie-Hellman.
            DiffieHellmanAgent alice = new DiffieHellmanAgent("Alice", groupInfo);
            DiffieHellmanAgent bob = new DiffieHellmanAgent("Bob", groupInfo);

            // They both share theirs public keys
            alice.Connect(bob);
            bob.Connect(alice);

            alice.AddRecord("alice-message");
            alice.SendLastRecord(bob);

            bob.AddRecord("bob-message");
            bob.SendLastRecord(alice);

            Console.WriteLine();
            Console.WriteLine("[Diffie-Hellman] Compare the 'Alice' and 'Bob' agents records...");

            if (alice.HasSameRecordsAs(bob) && bob.HasSameRecordsAs(alice))
            {
                Console.WriteLine($"[Diffie-Hellman] Successful! Alice and Bob have the same records as intended...");
            }
            else
            {
                Console.WriteLine($"[Diffie-Hellman] Failed! Alice and Bob have mismatch in their records...");
            }
        }

        /**
         * Simple Linear Forward Shif Register (LFSR) 
         */
        static void RunSimpleLFSR()
        {
            int[] s = new int[4] { 1, 1, 1, 1};

            for (int step = 0; step < 20; step++)
            {
                Console.WriteLine(String.Join(' ', s));

                int temp = s[0];

                int res = 0;
                for (int i = s.Length - 1; i >= 0; i--)
                {
                    res = (res + s[i]) % 2;
                }
                s[0] = res;

                for (int i = 1; i < s.Length; i++)
                {
                    int copy = s[i];
                    s[i] = temp;
                    temp = copy;
                }
            }

        }

        static void Main(string[] args)
        {
            // RunSimpleLFSR();

            string dashesLine = new string('-', 200);

            Console.WriteLine(dashesLine);
            PerformCaesarCipher();
            Console.WriteLine(dashesLine);

            Console.WriteLine();

            Console.WriteLine(dashesLine);
            PerformVijinerCipher();
            Console.WriteLine(dashesLine);

            Console.WriteLine();

            Console.WriteLine(dashesLine);
            PerformElGamalCryptosystem();
            Console.WriteLine(dashesLine);

            Console.WriteLine();

            Console.WriteLine(dashesLine);
            PerformDiffieHellmanCryptoSystem();
            Console.WriteLine(dashesLine);
        }
    }
}
