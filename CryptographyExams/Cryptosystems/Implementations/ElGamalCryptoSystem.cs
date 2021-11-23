using Cryptosystems.Implementations.Contracts;
using Cryptosystems.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Cryptosystems.Implementations
{
    public class ElGamalCryptoSystem : IElGamalCryptoSystem
    {
        public string Decrypt(string encrypted, ElGamalEphemeralKey sessionKey, ElGamalPublicKey publicKey, BigInteger privateKey)
        {
            // Having our private key in addition to public key (P) and ephemeral key (session key),
            // we can calculate the Km (mask key). Having that, reversing the encruption is straightforward.
            BigInteger km = EncryptionUtils.ModularExponentiation(sessionKey.Ke, privateKey, publicKey.P);
            StringBuilder builder = new StringBuilder();

            // Decode the base 64 encryption string to get the masked numbers.
            IEnumerable<BigInteger> maskedSymbols = EncryptionUtils.DecodeFromBase64(encrypted).Split(',').Select(x => BigInteger.Parse(x));
            foreach (BigInteger ms in maskedSymbols)
            {
                // Masked symbol is calculated as s * Km at encryption, so to unmask it and respectively to decrypt it
                // we need just to reverse the multiplication -> s / Km.
                BigInteger unmaskedSymbol = ms / km;
                builder.Append((char) unmaskedSymbol);
            }

            return builder.ToString();
        }

        public Tuple<ElGamalEphemeralKey, string> Encrypt(string text, ElGamalPublicKey publicKey)
        {
            // Note: By convention, the d priv key should be chosen between 2 and P.
            // However for the ease of the calculation here we take the [2, 10^6] mod from P.
            BigInteger kpriv = 2 + EncryptionUtils.Mod(publicKey.P, new Random().Next(1, (int)Math.Pow(10, 6)));
            ElGamalEphemeralKey sessionKey = new ElGamalEphemeralKey(EncryptionUtils.ModularExponentiation(publicKey.Alpha, kpriv, publicKey.P));
            BigInteger km = EncryptionUtils.ModularExponentiation(publicKey.Kpub, kpriv, publicKey.P);

            List<BigInteger> encryptedData = new List<BigInteger>();
            foreach(char s in text)
            {
                BigInteger maskedSymbol = new BigInteger(s) * km;
                encryptedData.Add(maskedSymbol);
            }

            // For the ease of reading encode the numbers in string sequence -> base 64.
            string base64EncryptionData = EncryptionUtils.EncodeToBase64(String.Join(',', encryptedData));

            return new Tuple<ElGamalEphemeralKey, string>(sessionKey, base64EncryptionData);
        }

        public Tuple<ElGamalPublicKey, BigInteger> GenerateKeys()
        {
            // Generate the Alpha number, it should be really large.
            BigInteger alpha = EncryptionUtils.GetRandomInRange(new BigInteger(Math.Pow(10, 10)), 15);
            Console.WriteLine("WOOw");

            // Then select the P. P and Alpha should be mutually prime numbers.
            BigInteger p = 0;
            for (BigInteger i = alpha; i >= 0; i--)
            {
                if (EncryptionUtils.GCD(alpha, i) == 1)
                {
                    // p and alpha are mutually prime. (This means that there is an inverse in the ring).
                    p = i;
                    break;
                }
            }

            // Note: By convention, the d (private key) should be chosen between 2 and P.
            // However for the ease of the calculation here we take the [2, 10^6] mod from P.
            BigInteger kpriv = 2 + EncryptionUtils.Mod(p, new Random().Next(1, (int) Math.Pow(10, 6)));

            // Public key is calculated as Alpha^Kpriv mod P.
            BigInteger kpub = EncryptionUtils.ModularExponentiation(alpha, kpriv, p);

            return new Tuple<ElGamalPublicKey, BigInteger>(new ElGamalPublicKey(kpub, p, alpha), kpriv);
        }
    }
}
