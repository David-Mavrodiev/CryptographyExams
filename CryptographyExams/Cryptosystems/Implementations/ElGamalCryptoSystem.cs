using Cryptosystems.Implementations.Contracts;
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
            BigInteger km = this.ModularExponentiation(sessionKey.Ke, privateKey, publicKey.P);
            StringBuilder builder = new StringBuilder();

            // Decode the base 64 encryption string to get the masked numbers.
            IEnumerable<BigInteger> maskedSymbols = this.DecodeFromBase64(encrypted).Split(',').Select(x => BigInteger.Parse(x));
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
            BigInteger kpriv = 2 + this.Mod(publicKey.P, new Random().Next(1, (int)Math.Pow(10, 6)));
            ElGamalEphemeralKey sessionKey = new ElGamalEphemeralKey(this.ModularExponentiation(publicKey.Alpha, kpriv, publicKey.P));
            BigInteger km = this.ModularExponentiation(publicKey.Kpub, kpriv, publicKey.P);

            List<BigInteger> encryptedData = new List<BigInteger>();
            foreach(char s in text)
            {
                BigInteger maskedSymbol = new BigInteger(s) * km;
                encryptedData.Add(maskedSymbol);
            }

            // For the ease of reading encode the numbers in string sequence -> base 64.
            string base64EncryptionData = this.EncodeToBase64(String.Join(',', encryptedData));

            return new Tuple<ElGamalEphemeralKey, string>(sessionKey, base64EncryptionData);
        }

        public Tuple<ElGamalPublicKey, BigInteger> GenerateKeys()
        {
            // Generate the Alpha number, it should be really large.
            BigInteger alpha = this.GetRandomInRange(new BigInteger(Math.Pow(10, 10)), 15);

            // Then select the P. It should be a prime number in the range of the (0, Alpha).
            BigInteger p = 0;
            for (BigInteger i = alpha / 2; i >= 0; i--)
            {
                if (this.GCD(alpha, i) == 1)
                {
                    p = i;
                    break;
                }
            }

            // Note: By convention, the d (private key) should be chosen between 2 and P.
            // However for the ease of the calculation here we take the [2, 10^6] mod from P.
            BigInteger kpriv = 2 + this.Mod(p, new Random().Next(1, (int) Math.Pow(10, 6)));

            // Public key is calculated as Alpha^Kpriv mod P.
            BigInteger kpub = this.ModularExponentiation(alpha, kpriv, p);

            return new Tuple<ElGamalPublicKey, BigInteger>(new ElGamalPublicKey(kpub, p, alpha), kpriv);
        }

        private string EncodeToBase64(string text)
        {
            byte[] bytes = ASCIIEncoding.ASCII.GetBytes(text);
            return Convert.ToBase64String(bytes);
        }

        private string DecodeFromBase64(string base64String)
        {
            byte[] bytes = Convert.FromBase64String(base64String);
            return ASCIIEncoding.ASCII.GetString(bytes);
        }

        private BigInteger ModularExponentiation(BigInteger b, BigInteger ex, BigInteger mod)
        {
            if (mod == 1)
            {
                return 0;
            }

            BigInteger c = 1;
            for (BigInteger i = 0; i < ex - 1; i++)
            {
                c = this.Mod((c * b), mod);
            }

            return c;
        }

        private BigInteger Mod(BigInteger x, BigInteger m)
        {
            return (x % m + m) % m;
        }

        private BigInteger GCD(BigInteger a, BigInteger b)
        {
            if (a < b)
            {
                return this.GCD(b, a);
            }

            if (a % b == 0)
            {
                return b;
            }

            return this.GCD(b, a % b);
        }

        private BigInteger GetRandomInRange(BigInteger from, int length)
        {
            byte[] bytes = new byte[length];
            new Random().NextBytes(bytes);
            // Set sign bit positive
            bytes[bytes.Length - 1] &= 0x7F;

            return from + new BigInteger(bytes);
        }
    }
}
