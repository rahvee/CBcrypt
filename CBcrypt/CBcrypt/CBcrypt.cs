using System;
// using CryptSharp.Utility;    // Today, doesn't conflict with bouncycastle. But bouncycastle has an implementation of SCrypt might come out someday
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;

namespace CBCrypt
{
    public static class CBCrypt
    {
        /// <summary>
        /// Applies RateLimitingFunction to the LowCostSecret.  Returns a HighCostSecret, dkLength = 32 bytes
        /// 
        /// NOTICE:  Zero's out LowCostSecret before returning.
        /// </summary>
        private static byte[] DoRateLimitingFunction(byte[] LowCostSecret)
        {
            /* cost 4096, blockSize 8, parallel 1, cause SCrypt to take ~175-350ms on Core i5-540M, 2.5Ghz
             * This is in addition to the approx 100ms-200ms to generate ECDSA keypair.
             */
            const int dkLength = 32;
            byte[] retVal = CryptSharp.Utility.SCrypt.ComputeDerivedKey
                (
                key: LowCostSecret,         // scrypt will transform this into a high cost secret
                salt: new byte[16],         // zero salt
                cost: 4096,                 // To scale the cost, scale this parameter.  Scale is approximately linear.
                blockSize: 8,               // this is a recommended default by the scrypt authors
                parallel: 1,                // this is a recommended default by the scrypt authors
                maxThreads: null,
                derivedKeyLength: dkLength  // 32 is surely large enough not to lose any entropy of the user supplied password
                );
            Array.Clear(LowCostSecret, 0, LowCostSecret.Length);
            return retVal;
        }

        /// <summary>
        /// Returns a seed generated from the parameters. Some day we may implement variants with different hashes,
        /// but for now it's hard-coded to use Sha256 returning 32 bytes.
        /// </summary>
        private static byte[] GetLowCostSecret(string CBCryptHostId, string username, string password)
        {
            if (CBCryptHostId == null)
            {
                throw new ArgumentNullException("CBCryptHostId");
            }
            if (username == null)
            {
                throw new ArgumentNullException("username");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            if (CBCryptHostId.Length < 1)
            {
                throw new ArgumentException("CBCryptHostId must not be blank");
            }
            if (username.Length < 1)
            {
                throw new ArgumentException("username must not be blank");
            }
            if (password.Length < 1)
            {
                throw new ArgumentException("password must not be blank");
            }
            byte[] CBCryptHostIdBytes = System.Text.Encoding.UTF8.GetBytes(CBCryptHostId);
            byte[] usernameBytes = System.Text.Encoding.UTF8.GetBytes(username);
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            /* We want to distill all the inputs down to a single hash, which is unique given the specific set of inputs.
             * It is important that we don't get the same hash output, if there's any variation of the inputs - in other words, 
             * we must be resilient to concatenation.
             *
             * The two ways readily available were to HMAC each input, in turn using the previous HMAC as the key for the next.  Or, 
             * first hash each input separately and independently of each other, and then hash a concatenation of all the hashes.
             * The second is slightly faster, as if that matters.  Which is why we're using it.
             */
            using (var hashFunction = System.Security.Cryptography.SHA256.Create())
            {
                // factorHashes : byte array that will contain the concatenated hashes of all the inputFactors
                int hashSizeInBytes = hashFunction.HashSize / 8;
                const int thisArgc = 3;
                var factorHashes = new byte[hashSizeInBytes * thisArgc];
                int factorHashesPos = 0;
                byte[] factorHash;

                factorHash = hashFunction.ComputeHash(CBCryptHostIdBytes);
                Array.Clear(CBCryptHostIdBytes, 0, CBCryptHostIdBytes.Length);
                Array.Copy(factorHash, 0, factorHashes, factorHashesPos, factorHash.Length);
                Array.Clear(factorHash, 0, factorHash.Length);
                factorHashesPos += hashSizeInBytes;

                factorHash = hashFunction.ComputeHash(usernameBytes);
                Array.Clear(usernameBytes, 0, usernameBytes.Length);
                Array.Copy(factorHash, 0, factorHashes, factorHashesPos, factorHash.Length);
                Array.Clear(factorHash, 0, factorHash.Length);
                factorHashesPos += hashSizeInBytes;

                factorHash = hashFunction.ComputeHash(passwordBytes);
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
                Array.Copy(factorHash, 0, factorHashes, factorHashesPos, factorHash.Length);
                Array.Clear(factorHash, 0, factorHash.Length);
                // factorHashesPos += hashSizeInBytes;      // this is actually unnecessary cuz it's the last one

                byte[] output = hashFunction.ComputeHash(factorHashes);
                Array.Clear(factorHashes, 0, factorHashes.Length);
                return output;
            }
        }

        /// <summary>
        /// Returns seeded PRNG
        /// Someday, we might want to add more variants on digests.  But for now, Sha256 is the only option.
        /// </summary>
        private static SecureRandom GetSeededDigestRandomGenerator(byte[] seed)
        {
            var prng = new DigestRandomGenerator(new Sha256Digest());
            prng.AddSeedMaterial(seed);
            return new SecureRandom(prng);
        }

        /// <summary>
        /// Returns the keypair derived from the parameters.
        /// Someday, we might want to add different types of Asymmetric Key Pairs.  But for now, ECDH/256 is 
        /// the only option.
        /// </summary>
        public static AsymmetricCipherKeyPair GenerateKeyPair(string CBCryptHostId, string username, string password)
        {
            byte[] lowCostSecret = GetLowCostSecret(CBCryptHostId, username, password);
            byte[] highCostSecret = DoRateLimitingFunction(lowCostSecret);
            SecureRandom seededPRNG = GetSeededDigestRandomGenerator(highCostSecret);

            // Algorithm possibilities:  "EC", "ECDSA", "ECDH", "ECDHC", "ECGOST3410", "ECMQV"
            // Default if none specified:  "EC"
            var ec = new ECKeyPairGenerator("ECDH");
            // strength parameters:  192, 224, 239, 256, 384, 521
            var keyGenParams = new KeyGenerationParameters(seededPRNG, 256);
            ec.Init(keyGenParams);

            return ec.GenerateKeyPair();
        }
    }
}
