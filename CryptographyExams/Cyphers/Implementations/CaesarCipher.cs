using Cyphers.Implementations.Base;
using Cyphers.Implementations.Contracts;
using System.Text;
using static Cyphers.Implementations.Contracts.CaesarCipherKey;

namespace Cyphers.Implementations
{
    public class CaesarCipher : BaseAlphabetCipher<CaesarCipherKey>, ICaesarCipher
    {
        public override string Decrypt(string encrypted, CaesarCipherKey key)
        {
            // Decryption is just an encruption with the reversed shift key.
            CaesarCipherKey reversedKey = new CaesarCipherKey(key.Orientation, -key.Shift);
            return this.Encrypt(encrypted, reversedKey);
        }

        public override string Encrypt(string target, CaesarCipherKey key)
        {
            int orientationCoef = key.Orientation == CaesarCipherOrientation.LEFT ? -1 : 1;
            StringBuilder builder = new StringBuilder();
            foreach (char symbol in target)
            {
                int translationAlphabetIndex = this.Mod(this.GetAlphabetIndex(symbol) + key.Shift * orientationCoef, 26);
                builder.Append(this.getAsciiByAlphabetIndex(translationAlphabetIndex));
            }
            return builder.ToString();
        }
    }
}
