using Cryptosystems.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace Cryptosystems.Implementations
{
    public class DiffieHellmanCryptoSystem
    {
        public static DiffieHellmanCyclicPrimeGroupInfo GenerateCyclicPrimeGroupInfo()
        {
            DiffieHellmanCyclicPrimeGroupInfo groupInfo = new DiffieHellmanCyclicPrimeGroupInfo();
            groupInfo.P = EncryptionUtils.GetRandomPrime();

            // Find a co-prime to P backwards.
            for (BigInteger i = groupInfo.P / 2; i >= 2; i--)
            {
                if (EncryptionUtils.GCD(groupInfo.P, i) == 1)
                {
                    // Found a "generator" of the P group.
                    groupInfo.Alpha = i;
                    break;
                }
            }

            return groupInfo;
        }

        public static DiffieHellmanKeyPair GenerateKeyPair(DiffieHellmanCyclicPrimeGroupInfo groupInfo)
        {
            DiffieHellmanKeyPair pair = new DiffieHellmanKeyPair(groupInfo);

            // For the private key just get some random number.
            pair.PrivateKey = new Random().Next(2, (int) Math.Pow(2, 12));

            return pair;
        }

        public static string Encrypt(string target, BigInteger sharedSecret)
        {
            List<BigInteger> encryptedData = new List<BigInteger>();
            foreach (char s in target)
            {
                BigInteger maskedSymbol = new BigInteger(s) * sharedSecret;
                encryptedData.Add(maskedSymbol);
            }

            // For the ease of reading encode the numbers in string sequence -> base 64.
            return EncryptionUtils.EncodeToBase64(String.Join(',', encryptedData));
        }

        public static string Decrypt(string encrypted, BigInteger sharedSecret)
        {
            StringBuilder builder = new StringBuilder();

            // Decode the base 64 encryption string to get the masked numbers.
            IEnumerable<BigInteger> maskedSymbols = EncryptionUtils.DecodeFromBase64(encrypted).Split(',').Select(x => BigInteger.Parse(x));
            foreach (BigInteger ms in maskedSymbols)
            {
                BigInteger unmaskedSymbol = ms / sharedSecret;
                builder.Append((char)unmaskedSymbol);
            }

            return builder.ToString();
        }
    }

    /**
     * Represents an endpoint that wants to securely communicate with another endpoint (using Diffie-Hellman for encryption).
     */
    public class DiffieHellmanAgent
    {
        private readonly DiffieHellmanKeyPair keyPair;
        private readonly HashSet<string> records = new HashSet<string>();
        private readonly string name;

        private BigInteger sharedSecret;
        private string lastAddedRecord;

        public string[] Records
        {
            get
            {
                return this.records.ToArray();
            }
        }

        public DiffieHellmanAgent(string name, DiffieHellmanCyclicPrimeGroupInfo groupInfo)
        {
            this.name = name;
            this.keyPair = DiffieHellmanCryptoSystem.GenerateKeyPair(groupInfo);
        }

        public void OnConnect(BigInteger publicKey)
        {
            Console.WriteLine($"[Diffie-Hellman-Sim](Connect) {name} received '{publicKey}' as public key...");
            this.sharedSecret = EncryptionUtils.ModularExponentiation(publicKey, this.keyPair.PrivateKey, this.keyPair.PrimeCyclicGroupInfo.P);
        }

        public void OnReceive(string encrypted)
        {
            Console.WriteLine($"[Diffie-Hellman-Sim](Receive) {name} received '{encrypted}' as encrypted text...");
            string decryptedText = DiffieHellmanCryptoSystem.Decrypt(encrypted, this.sharedSecret);

            Console.WriteLine($"[Diffie-Hellman-Sim](Receive) {name} decrypted '{encrypted}' to '{decryptedText}'...");

            Console.WriteLine($"[Diffie-Hellman-Sim](Receive) {name} added decrypted received record '{decryptedText}' to his records log...");
            this.records.Add(decryptedText);
        }

        /**
         * Sends public key to the passed agent receiver.
         */
        public DiffieHellmanAgent Connect(DiffieHellmanAgent receiver)
        {
            receiver.OnConnect(this.keyPair.PublicKey);
            return this;
        }

        public void AddRecord(string text)
        {
            Console.WriteLine($"[Diffie-Hellman-Sim](Write) {name} write '{text}' to his records log...");
            this.lastAddedRecord = text;
            this.records.Add(text);
        }

        private string GetEncryptedLastRecord()
        {
            return DiffieHellmanCryptoSystem.Encrypt(this.lastAddedRecord, this.sharedSecret);
        }

        public void SendLastRecord(DiffieHellmanAgent receiver)
        {
            string encryptedLastLog = this.GetEncryptedLastRecord();
            Console.WriteLine($"[Diffie-Hellman-Sim](Send) {name} encrypts the last record '{this.lastAddedRecord}' to '{encryptedLastLog}'...");
            Console.WriteLine($"[Diffie-Hellman-Sim](Send) {name} sends the last record (encrypted) '{encryptedLastLog}'...");
            receiver.OnReceive(encryptedLastLog);
        }

        public bool HasSameRecordsAs(DiffieHellmanAgent agent)
        {
            foreach (string record in records)
            {
                bool isContained = this.records.Contains(record);
                if (!isContained)
                {
                    return false;
                }
            }

            return true;
        }
    }

    public class DiffieHellmanCyclicPrimeGroupInfo
    {
        /**
         * This is a "generator" of an cyclic prime group (additive or multiplicative) of P.
         */
        public BigInteger Alpha { get; set; }

        /**
         * Group of prime.
         * NOTE: In all prime groups there is AT LEAST one "generator" element.
         */
        public BigInteger P { get; set; }
    }

    public class DiffieHellmanKeyPair
    {
        public DiffieHellmanKeyPair(DiffieHellmanCyclicPrimeGroupInfo groupInfo)
        {
            this.PrimeCyclicGroupInfo = groupInfo;
        }

        public BigInteger PrivateKey { get; set; }

        public DiffieHellmanCyclicPrimeGroupInfo PrimeCyclicGroupInfo { get; set; }

        public BigInteger PublicKey
        {
            get
            {
                return EncryptionUtils.ModularExponentiation(this.PrimeCyclicGroupInfo.Alpha, this.PrivateKey, this.PrimeCyclicGroupInfo.P);
            }
        }
    }
}
