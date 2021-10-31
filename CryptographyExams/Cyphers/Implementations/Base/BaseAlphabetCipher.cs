namespace Cyphers.Implementations.Base
{
    public abstract class BaseAlphabetCipher<TKey>
    {
        protected static readonly char STARTING_SYMBOL = 'A';

        protected int GetAlphabetIndex(char s)
        {
            return s - STARTING_SYMBOL;
        }

        protected char getAsciiByAlphabetIndex(int index)
        {
            return (char)(index + STARTING_SYMBOL);
        }

        protected int Mod(int x, int m)
        {
            return (x % m + m) % m;
        }

        public abstract string Decrypt(string encrypted, TKey key);

        public abstract string Encrypt(string target, TKey key);
    }
}
