using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

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

        public static BigInteger ModularExponentiation(BigInteger @base, BigInteger exponent, BigInteger factor)
        {
            @base = @base % factor;
            if (@base == 0)
            {
                // @base is divisible by the factor so the mod is 0.
                return 0;
            }

            BigInteger result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                {
                    result = (result * @base) % factor;
                }

                exponent = exponent >> 1; // equivalent to division by 2.
                @base = (@base * @base) % factor;
            }

            return result;
        }

        public static BigInteger FindGeneratorOfPrimeOrder(BigInteger prime)
        {
            IDictionary<BigInteger, BigInteger> primeFactors = PrimeFactorization(prime - 1);

            for (BigInteger generatorCandidate = prime - 1; generatorCandidate >= 2; generatorCandidate --)
            {
                bool isGenerator = true;
                foreach (BigInteger factor in primeFactors.Keys)
                {
                    BigInteger result = ModularExponentiation(generatorCandidate, (prime - 1) / factor, prime);
                    if (result == 1)
                    {
                        isGenerator = false;
                        break;
                    }
                }

                if (isGenerator)
                {
                    return generatorCandidate;
                }
            }

            return 2;
        }

        public static bool VerifyIsGenerator(BigInteger generator, BigInteger order)
        {
            HashSet<BigInteger> generatedElements = new HashSet<BigInteger>();
            for (int i = 1; i < order; i++)
            {
                generatedElements.Add(ModularExponentiation(generator, i, order));
            }

            return generatedElements.Count == order - 1;
        }

        public static IDictionary<BigInteger, BigInteger> PrimeFactorization(BigInteger number)
        {
            var primeFactorsWithCoeffs = new Dictionary<BigInteger, BigInteger>();

            for (BigInteger div = 2; div <= number; div++)
            {
                BigInteger coeff = 0;
                while (number % div == 0)
                {
                    coeff ++;
                    number = number / div;
                }
                if (coeff > 0)
                {
                    primeFactorsWithCoeffs.Add(div, coeff);
                }
            }

            return primeFactorsWithCoeffs;
        }

        public static BigInteger Mod(BigInteger x, BigInteger m)
        {
            return (x % m + m) % m;
        }

        public static BigInteger GCD(BigInteger a, BigInteger b)
        {
            if (a < b)
            {
                return GCD(b, a);
            }

            if (a % b == 0)
            {
                return b;
            }

            return GCD(b, a % b);
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

            int randomNumber = new Random().Next(2, lengthOfShieve);
            int randomIndex = (int) Mod(randomNumber, primes.Count);

            return primes[randomIndex];
        }
    }
}
