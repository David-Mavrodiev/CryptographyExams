using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptosystems.Utils
{
    public class EncryptionUtils
    {
        public static string EncodeToBase64(string text)
        {
            byte[] bytes = ASCIIEncoding.ASCII.GetBytes(text);
            return Convert.ToBase64String(bytes);
        }

        public static string DecodeFromBase64(string base64String)
        {
            byte[] bytes = Convert.FromBase64String(base64String);
            return ASCIIEncoding.ASCII.GetString(bytes);
        }

        public static BigInteger ModularExponentiation(BigInteger b, BigInteger ex, BigInteger mod)
        {
            if (mod == 1)
            {
                return 0;
            }

            BigInteger c = 1;
            for (BigInteger i = 0; i < ex - 1; i++)
            {
                c = EncryptionUtils.Mod((c * b), mod);
            }

            return c;
        }

        public static BigInteger Mod(BigInteger x, BigInteger m)
        {
            return (x % m + m) % m;
        }

        public static BigInteger GCD(BigInteger a, BigInteger b)
        {
            if (a < b)
            {
                return EncryptionUtils.GCD(b, a);
            }

            if (a % b == 0)
            {
                return b;
            }

            return EncryptionUtils.GCD(b, a % b);
        }

        public static BigInteger GetRandomInRange(BigInteger from, int length)
        {
            byte[] bytes = new byte[length];
            new Random().NextBytes(bytes);
            // Set sign bit positive
            bytes[bytes.Length - 1] &= 0x7F;

            return from + new BigInteger(bytes);
        }


        /**
         * Get random prime number using the Sieve of Eratosthenes (the simplest, but the most uneffective approach of generating primes :-)).
         * NOTE: The size of the number and the approach of the generation are NOT cryptographically secure. It is just used for the sake of proof of concept. 
         */
        public static BigInteger GetRandomPrime()
        {
            int lengthOfShieve = (int) Math.Pow(2, 12);
            bool[] isNotPrime = new bool[lengthOfShieve];
            List<int> primes = new List<int>();

            for (int i = 2; i < lengthOfShieve; i++)
            {
                if (isNotPrime[i])
                {
                    continue;
                }

                primes.Add(i);

                for (int j = i + 1; j < lengthOfShieve; j++)
                {
                    if (j % i == 0)
                    {
                        isNotPrime[j] = true;
                    }
                }
            }

            int randomNumber = (int) new BigInteger(new Random().Next(2, lengthOfShieve));
            int randomIndex = (int) EncryptionUtils.Mod(randomNumber, new BigInteger(primes.Count));

            return new BigInteger(primes[randomIndex]);
        }
    }
}
