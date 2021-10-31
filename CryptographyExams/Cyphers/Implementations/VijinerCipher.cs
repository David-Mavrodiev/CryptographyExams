using Cyphers.Implementations.Base;
using Cyphers.Implementations.Contracts;
using System.Text;

namespace Cyphers.Implementations
{
    public class VijinerCipher : BaseAlphabetCipher<string>, IVijinerCipher
    {
        public override string Decrypt(string encrypted, string key)
        {
            key = TransformKeyByLength(encrypted, key);
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < encrypted.Length; i++)
            {
                int alphabetIndex = this.Mod(this.GetAlphabetIndex(encrypted[i]) - this.GetAlphabetIndex(key[i]), 26);
                builder.Append(this.getAsciiByAlphabetIndex(alphabetIndex));
            }

            return builder.ToString();
        }

        public override string Encrypt(string target, string key)
        {
            key = TransformKeyByLength(target, key);
            StringBuilder builder = new StringBuilder();

            for (int i = 0; i < target.Length; i++)
            {
                int alphabetIndex = this.Mod(this.GetAlphabetIndex(target[i]) + this.GetAlphabetIndex(key[i]), 26);
                builder.Append(this.getAsciiByAlphabetIndex(alphabetIndex));
            }

            return builder.ToString();
        }

        private string TransformKeyByLength(string text, string key)
        {
            if (text.Length < key.Length)
            {
                return key.Substring(0, text.Length);
            }

            int fillsCount = text.Length - key.Length;
            int index = 0;

            StringBuilder builder = new StringBuilder();
            builder.Append(key);

            while (fillsCount > 0)
            {
                builder.Append(key[index]);

                fillsCount --;
                index ++;

                if (index == key.Length)
                {
                    index = 0;
                }
            }

            return builder.ToString();
        }
    }
}
