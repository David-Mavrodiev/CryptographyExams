namespace Cyphers.Implementations.Contracts
{
    public interface IVijinerCipher
    {
        string Encrypt(string target, string key);

        string Decrypt(string encrypted, string key);
    }
}
