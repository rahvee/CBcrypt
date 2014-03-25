using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CBcryptlib;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Math;
using CryptSharp.Utility;
using System.Security.Cryptography;
using System.IO;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var exampleServer = new ExampleServer();

            var exampleUser = new ExampleUser();

            // I had to do this once, to populate the constructor of ExampleServer
            // No longer necessary, so commented-out.
            // AsymmetricKeyParameter userPublicKey = exampleUser.GetPublicKey();
            // exampleServer.SaveUser("syndrome", userPublicKey);

            if ( exampleUser.TryAuthentication(exampleServer) )
            {
                System.Console.WriteLine("Success");
            }
            else
            {
                System.Console.WriteLine("Failure");
            }

            System.Console.Out.Flush();
            System.Threading.Thread.Sleep(int.MaxValue);
        }
    }
    class ExampleUser
    {
        private string username;
        private AsymmetricCipherKeyPair PrivateKeyPair;

        public ExampleUser()
        {
            byte[] exampleServerName = Encoding.UTF8.GetBytes("foobar.example.com");
            int examplePortNumber = 443;
            byte[] examplePortNumberBytes = BitConverter.GetBytes(examplePortNumber);
            if (BitConverter.IsLittleEndian)
                examplePortNumberBytes.Reverse();

            this.username = "syndrome";
            byte[] exampleUsername = Encoding.UTF8.GetBytes(this.username);

            byte[] examplePassword = Encoding.UTF8.GetBytes("Kronos");

            // It doesn't matter what order you add them in, as long as you're consistent.
            // If you change the order and generate key with all the same inputs in a different order,
            // you will get a different key and hence be unable to authenticate as the same user who
            // originally authenticated with the factors in the original order.
            var factors = new List<byte[]>();
            factors.Add(exampleServerName);
            factors.Add(examplePortNumberBytes);
            factors.Add(exampleUsername);
            factors.Add(examplePassword);

            this.PrivateKeyPair = CBcrypt.GenerateKeyPair(factors);
        }
        public AsymmetricKeyParameter GetPublicKey()
        {
            return this.PrivateKeyPair.Public;
        }
        public bool TryAuthentication (ExampleServer server)
        {
            // I send a request for authentication to the server with my public key.
            // The server responds with a random message, encrypted by the negotiated shared secret
            byte[] challengeCiphertext = server.TryAuthenticatePhase1(this.username, this.PrivateKeyPair.Public);

            var agreement = new ECDHBasicAgreement();
            agreement.Init(this.PrivateKeyPair.Private);
            byte[] sharedSecretBytes = agreement.CalculateAgreement(server.GetPublicKey()).ToByteArrayUnsigned();

            byte[] challengePlaintext = new byte[16];
            byte[] aesIV = new byte[16];
            Array.Clear(aesIV, 0, aesIV.Length);
            using (var aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;  // We are going to do a single block, so ECB is ok.
                aes.IV = aesIV;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.None;
                aes.Key = sharedSecretBytes;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                decryptor.TransformBlock(challengeCiphertext, 0, challengeCiphertext.Length, challengePlaintext, 0);
            }

            return server.TryAuthenticatePhase2(this.username, challengePlaintext);
        }
    }
    class ExampleServer
    {
        private class UserInfo
        {
            public byte[] Salt;
            public byte[] SCryptHashOfPublicKey;
            public byte[] CurrentAuthAttemptCorrectDecryptedChallenge;
        }
        private AsymmetricCipherKeyPair PrivateKeyPair;
        private Dictionary<string,UserInfo> userDatabase;

        public ExampleServer()
        {
            // Periodically, the server should generate a new key, for the heck of it.
            byte[] randomBytes = new byte[32];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);

            this.PrivateKeyPair = CBcrypt.GenerateKeyPair(randomBytes);

            // Pretend we have a database full of users.  In reality, we have this hard-coded object containing only one
            // user.  Because I'm just a simple ExampleServer.
            this.userDatabase = new Dictionary<string,UserInfo>();
            // The following values for salt & SCryptHashOfPublicKey, I got once, by generating a salt, generating the public key of syndrome,
            // SCrypt hashing it, and making a copy of the salt & hash.  Pasted below.  Via SaveUser.
            var newUserInfo = new UserInfo();
            newUserInfo.Salt = Convert.FromBase64String("uAtNXeGMq8CzLl7JtcEO58Hx43As5qAPC1zJ0rYZkMw=");
            newUserInfo.SCryptHashOfPublicKey = Convert.FromBase64String("+jLD0VKKPBKa2h1g+qOuwpGAwzRziAIs7QDLCrU4ARA=");
            this.userDatabase["syndrome"] = newUserInfo;
        }
        public void SaveUser(string username, AsymmetricKeyParameter clientPublicKey)
        {
            // This method doesn't actually save anything.  It just generates a string, sequence of bytes, that you the programmer
            // can copy & paste into source code, so the user can exist next time you run the program.  Because this is just a simple
            // ExampleServer.
            var myRandomSalt = new byte[32];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(myRandomSalt);

            string publicKeyString;
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(clientPublicKey);
                pemWriter.Writer.Flush();
                publicKeyString = stringWriter.ToString();
            }
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes( publicKeyString );

            var SCryptParams = new SCryptParameters()   // These parameters cause SCrypt to take ~175-350ms on Core i5-540M, 2.5Ghz
            {
                blockSize = 2,
                cost = 16384,
                parallel = 1,
                maxThreads = null,
                key = publicKeyBytes,
                salt = myRandomSalt,
                derivedKeyLength = 32,
            };
            byte[] sCryptBytes = SCrypt.ComputeDerivedKey
                (
                key: SCryptParams.key, 
                salt: SCryptParams.salt, 
                cost: SCryptParams.cost, 
                blockSize: SCryptParams.blockSize, 
                parallel: SCryptParams.parallel, 
                maxThreads: SCryptParams.maxThreads, 
                derivedKeyLength: SCryptParams.derivedKeyLength
                );
            string myRandomSaltBase64 = Convert.ToBase64String(myRandomSalt);
            string sCryptBase64 = Convert.ToBase64String(sCryptBytes);

            // Here is a convenient breakpoint, so you can copy those strings and paste into the constructor for next time.
            System.Diagnostics.Debugger.Break();
        }
        /// <summary>
        /// Returns an encrypted challenge. The user must then decrypt and send it back, to confirm their identity
        /// </summary>
        public byte[] TryAuthenticatePhase1(string username, AsymmetricKeyParameter clientPublicKey)
        {
            UserInfo userInfo = null;

            byte[] challengePlaintext = new byte[16];
            new RNGCryptoServiceProvider().GetBytes(challengePlaintext);

            var agreement = new ECDHBasicAgreement();
            agreement.Init(this.PrivateKeyPair.Private);
            byte[] sharedSecretBytes = agreement.CalculateAgreement(clientPublicKey).ToByteArrayUnsigned();

            byte[] challengeCiphertext = new byte[16];
            byte[] aesIV = new byte[16];
            Array.Clear(aesIV,0,aesIV.Length);
            using (var aes = new AesManaged())
            {
                aes.Mode = CipherMode.ECB;  // We are going to do a single block, so ECB is ok.
                aes.IV = aesIV;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.None;
                aes.Key = sharedSecretBytes;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key,aes.IV);
                encryptor.TransformBlock(challengePlaintext, 0, challengePlaintext.Length, challengeCiphertext, 0);
            }

            string publicKeyString;
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(clientPublicKey);
                pemWriter.Writer.Flush();
                publicKeyString = stringWriter.ToString();
            }
            byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKeyString);

            var SCryptParams = new SCryptParameters()   // These parameters cause SCrypt to take ~175-350ms on Core i5-540M, 2.5Ghz
            {
                blockSize = 2,
                cost = 16384,
                parallel = 1,
                maxThreads = null,
                key = publicKeyBytes,
                salt = null,
                derivedKeyLength = 32,
            };

            if (this.userDatabase.TryGetValue(username, out userInfo))
            {
                // Yes the user exists
                SCryptParams.salt = userInfo.Salt;
                byte[] sCryptBytes = SCrypt.ComputeDerivedKey
                    (
                    key: SCryptParams.key,
                    salt: SCryptParams.salt,
                    cost: SCryptParams.cost,
                    blockSize: SCryptParams.blockSize,
                    parallel: SCryptParams.parallel,
                    maxThreads: SCryptParams.maxThreads,
                    derivedKeyLength: SCryptParams.derivedKeyLength
                    );
                bool publicKeyMatches = true;
                if (sCryptBytes.Length == userInfo.SCryptHashOfPublicKey.Length)
                {
                    for (int i = 0; i < sCryptBytes.Length; i++)
                    {
                        if (sCryptBytes[i] != userInfo.SCryptHashOfPublicKey[i])
                        {
                            publicKeyMatches = false;
                            break;
                        }
                    }
                }
                else
                {
                    throw new Exception("The programmer has made a mistake");
                }
                if (publicKeyMatches)
                {
                    userInfo.CurrentAuthAttemptCorrectDecryptedChallenge = challengePlaintext;
                }
                else
                {
                    userInfo.CurrentAuthAttemptCorrectDecryptedChallenge = null;
                }
                return challengeCiphertext;
            }
            else
            {
                // I'm just going to throw away this hash, but I shouldn't expose to the user, the fact that the username doesn't exist.
                // So I must waste time calculating, for the purpose of wasting time calculating.  To avoid timing attacks.
                SCryptParams.salt = new byte[32];
                Array.Clear(SCryptParams.salt, 0, SCryptParams.salt.Length);
                byte[] sCryptBytes = SCrypt.ComputeDerivedKey
                    (
                    key: SCryptParams.key,
                    salt: SCryptParams.salt,
                    cost: SCryptParams.cost,
                    blockSize: SCryptParams.blockSize,
                    parallel: SCryptParams.parallel,
                    maxThreads: SCryptParams.maxThreads,
                    derivedKeyLength: SCryptParams.derivedKeyLength
                    );

                // If they try to authenticate as a nonexistent user, we should not expose this fact.  Send them
                // the encrypted challenge response anyway.
                return challengeCiphertext;
            }
        }
        public bool TryAuthenticatePhase2(string username, byte[] challengeResponse)
        {
            UserInfo userInfo = null;

            if (this.userDatabase.TryGetValue(username, out userInfo))
            {
                if (userInfo.CurrentAuthAttemptCorrectDecryptedChallenge != null)
                {
                    if (challengeResponse == null)
                        return false;
                    if (challengeResponse.Length != userInfo.CurrentAuthAttemptCorrectDecryptedChallenge.Length)
                        return false;
                    for (int i=0; i<challengeResponse.Length; i++)
                    {
                        if (challengeResponse[i] != userInfo.CurrentAuthAttemptCorrectDecryptedChallenge[i])
                        {
                            return false;
                        }
                    }
                    // The user has successfully decrypted the challenge, and therefore is authenticated
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        public AsymmetricKeyParameter GetPublicKey()
        {
            return this.PrivateKeyPair.Public;
        }
    }
}
