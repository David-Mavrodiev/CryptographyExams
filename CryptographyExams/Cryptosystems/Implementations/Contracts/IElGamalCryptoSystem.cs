using System;
using System.Numerics;

namespace Cryptosystems.Implementations.Contracts
{
    public interface IElGamalCryptoSystem
    {
        Tuple<ElGamalPublicKey, BigInteger> GenerateKeys();

        Tuple<ElGamalEphemeralKey, string> Encrypt(string text, ElGamalPublicKey publicKey);

        string Decrypt(string encrypted, ElGamalEphemeralKey sessionKey, ElGamalPublicKey publicKey, BigInteger privateKey);
    }

    public class ElGamalPublicKey
    {
        public ElGamalPublicKey(BigInteger kpub, BigInteger p, BigInteger alpha)
        {
            this.Kpub = kpub;
            this.P = p;
            this.Alpha = alpha;
        }

        /**
         * The public key -> alpha^d. The d is a private key.
         */
        public BigInteger Kpub { get; set; }

        /**
         * The prime number chosen from Alpha.
         */
        public BigInteger P { get; set; }

        /**
         * Very large number - randomly generated.
         */
        public BigInteger Alpha { get; set; }
    }

    public class ElGamalEphemeralKey
    {
        public ElGamalEphemeralKey(BigInteger ke)
        {
            this.Ke = ke;
        }

        /**
         * Session key
         */
        public BigInteger Ke { get; set; }
    }
}
