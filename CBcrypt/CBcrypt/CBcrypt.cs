using System;
using System.Collections.Generic;
using CryptSharp.Utility;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;

namespace CBcryptlib
{
    public class SCryptParameters
    {
        /// <summary>
        /// The key to derive from.
        /// </summary>
        public byte[] key;

        /// <summary>
        /// The salt.  A unique salt means a unique SCrypt stream, even if the original
        /// key is identical.
        /// </summary>
        public byte[] salt;
        
        /// <summary>
        /// The cost parameter, typically a fairly large number such as 262144.  Memory
        /// usage and CPU time scale approximately linearly with this parameter.
        /// </summary>
        public int cost;
        
        /// <summary>
        /// The mixing block size, typically 8.  Memory usage and CPU time scale approximately
        /// linearly with this parameter.
        /// </summary>
        public int blockSize;
        
        /// <summary>
        /// The level of parallelism, typically 1.  CPU time scales approximately linearly
        /// with this parameter.
        /// </summary>
        public int parallel;
        
        /// <summary>
        /// The maximum number of threads to spawn to derive the key.  This is limited
        /// by the parallel value.  null will use as many threads as possible.
        /// </summary>
        public int? maxThreads;
        
        /// <summary>
        /// The desired length of the derived key.
        /// </summary>
        public int derivedKeyLength;
    }
    public static class CBcrypt
    {
        /// <summary>
        /// Some day we may implement other rate-limiting functions, but for now SCrypt is the only option.
        /// </summary>
        public static byte[] DoWorkfactor (byte[] preWorkFactorSecret)
        {
            // If any salt is going to be used, it has already been folded into the preWorkFactorSecret, so it's not needed here.
            // I am not sure if any implementations of SCrypt require the salt to be non-null, or a specific length,
            // so the following I'm sure, will work.
            var zeroSalt = new byte[32];
            Array.Clear(zeroSalt,0,zeroSalt.Length);

            var SCryptParams = new SCryptParameters()   // These parameters cause SCrypt to take ~175-350ms on Core i5-540M, 2.5Ghz
            {
                blockSize = 2,
                cost = 16384,
                parallel = 1,
                maxThreads = null,
                key = preWorkFactorSecret,
                salt = zeroSalt,
                derivedKeyLength = 32,
            };

            return DoWorkfactor(SCryptParams);
        }
        public static byte[] DoWorkfactor (SCryptParameters SCryptParams)
        {
            // long before = DateTime.UtcNow.Ticks;
            byte[] retVal = SCrypt.ComputeDerivedKey
                (
                key: SCryptParams.key, 
                salt: SCryptParams.salt, 
                cost: SCryptParams.cost, 
                blockSize: SCryptParams.blockSize, 
                parallel: SCryptParams.parallel, 
                maxThreads: SCryptParams.maxThreads, 
                derivedKeyLength: SCryptParams.derivedKeyLength
                );
            // long after = DateTime.UtcNow.Ticks;
            // double elapsed = ((double)(after - before)) / TimeSpan.TicksPerSecond;
            // System.Console.Error.WriteLine(elapsed.ToString());
            return retVal;
        }
        /// <summary>
        /// Returns a seed generated from the inputFactors.  At least 1 inputFactor must be provided
        /// null is disallowed, and zero-length is disallowed.  Some day we may implement variants with different hashes,
        /// but for now it's hard-coded to use Sha256 returning 32 bytes
        /// </summary>
        public static byte[] GetPreWorkfactorSecret(IList<byte[]> inputFactors)
        {
            if (inputFactors == null)
            {
                throw new ArgumentNullException("inputFactors");
            }
            if (inputFactors.Count < 1)
            {
                throw new ArgumentException("inputFactors must have at least 1 component, and recommend at least hostname, username, and password");
            }
            byte[] hmacKey = new byte[32];
            Array.Clear(hmacKey, 0, hmacKey.Length);
            foreach (byte[] inputFactor in inputFactors)
            {
                if (inputFactor == null)
                {
                    throw new ArgumentNullException("inputFactors");
                }
                if (inputFactor.Length == 0)
                {
                    throw new ArgumentException("inputFactors must not be zero-length");
                }
                using (var hmac = new System.Security.Cryptography.HMACSHA256(hmacKey))
                {
                    hmacKey = hmac.ComputeHash(inputFactor);
                }
            }
            return hmacKey;
        }
        /// <summary>
        /// Someday, we might want to add more variants on digests.  But for now, Sha256 is the only option.
        /// </summary>
        public static SecureRandom GetSeededDigestRandomGenerator(byte[] seed)
        {
            // By default, SecureRandom creates Sha1Digest with 8 bytes of seed based on DateTime.Now.Ticks.  
            // Which is not very secure at all.  But we won't do anything of the sort.
            var prng = new DigestRandomGenerator(new Sha256Digest());
            prng.AddSeedMaterial(seed);
            return new SecureRandom(prng);
        }
        /// <summary>
        /// Someday, we might want to add different types of Asymmetric Key Pairs.  But for now, ECDH 256 is the only option.
        /// </summary>
        public static AsymmetricCipherKeyPair GenerateKeyPair(byte[] Factor)
        {
            List<byte[]> factors = new List<byte[]>();
            factors.Add(Factor);
            return GenerateKeyPair(factors);
        }
        public static AsymmetricCipherKeyPair GenerateKeyPair(IList<byte[]> Factors)
        {
            byte[] preWorkFactorSecret = GetPreWorkfactorSecret(Factors);
            byte[] postWorkFactorSecret = DoWorkfactor(preWorkFactorSecret);
            SecureRandom seededPRNG = GetSeededDigestRandomGenerator(postWorkFactorSecret);

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
