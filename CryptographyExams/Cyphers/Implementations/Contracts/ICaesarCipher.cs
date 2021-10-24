namespace Cyphers.Implementations.Contracts
{
    /**
     * Describes the CaesarCipher behaviour.
     */
    public interface ICaesarCipher
    {
        string Encrypt(string target, CaesarCipherKey key);

        string Decrypt(string encrypted, CaesarCipherKey key);
    }

    /**
     * Contains all key information for encryption/decryption.
     */
    public class CaesarCipherKey
    {
        public CaesarCipherKey(CaesarCipherOrientation orientation, int shift)
        {
            this.Orientation = orientation;
            this.Shift = shift;
        }

        public CaesarCipherOrientation Orientation { get; set; }

        public int Shift { get; set; }

        /**
         * Describes the direction of which the target text should be shifted.
         */
        public enum CaesarCipherOrientation
        {
            LEFT,
            RIGHT
        }
    }
}
