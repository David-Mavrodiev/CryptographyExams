using Cyphers.Implementations.Contracts;
using System.Text;
using static Cyphers.Implementations.Contracts.CaesarCipherKey;

namespace Cyphers.Implementations
{
    public class CaesarCipher : ICaesarCipher
    {
        private static readonly char STARTING_SYMBOL = 'A';

        public string Decrypt(string encrypted, CaesarCipherKey key)
        {
            // Decryption is just an encruption with the reversed shift key.
            CaesarCipherKey reversedKey = new CaesarCipherKey(key.Orientation, -key.Shift);
            return this.Encrypt(encrypted, reversedKey);
        }

        public string Encrypt(string target, CaesarCipherKey key)
        {
            int orientationCoef = key.Orientation == CaesarCipherOrientation.LEFT ? -1 : 1;
            StringBuilder builder = new StringBuilder();
            foreach (char symbol in target)
            {
                int alphabetIndex = symbol - STARTING_SYMBOL;
                int translation = this.Mod(alphabetIndex + key.Shift * orientationCoef, 26);
                int asciiIndex = translation + STARTING_SYMBOL;

                builder.Append((char)asciiIndex);
            }
            return builder.ToString();
        }

        private int Mod(int x, int m)
        {
            return (x % m + m) % m;
        }
    }
}
