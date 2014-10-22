using NUnit.Framework;
using System;
using CBCrypt;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math;
using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;

namespace NUnitTest
{
    public sealed class TraceConsoleListener : TraceListener
    {
        public static TraceConsoleListener Listener = new TraceConsoleListener();
        public override void Write(string message)
        {
            Console.Write(message);
        }
        public override void WriteLine(string message)
        {
            Console.WriteLine(message);
        }
    }

    [TestFixture()]
    public class Test
    {
        [SetUp()]
        public void Init()
        {
            if (false == Trace.Listeners.Contains(TraceConsoleListener.Listener))
                Trace.Listeners.Add(TraceConsoleListener.Listener);
        }

        [Test()]
        public void Test_CBCrypt_GenerateKeyPair()
        {
            /* Pretend a client wants to authenticate to a server, without exposing the user's password to the server.
             * The sequence of things that must happen are as follows:
             *   1. The client checks that CBCryptHostId matches the SSL Cert Subject.
             *   2. The client uses CBCrypt.GenerateKeyPair() to convert the password into a keypair.
             *   3. The client establishes a connection to the server for login.
             *   4. The server generates its own ECDH keypair (or uses some stored ECDH keypair).
             *      Server sends both the server public key, and a random generated challenge (16 bytes is good) to the client.
             *   5. Client uses its private key with server public key, to generate derived secret.  HMAC sign the challenge using
             *      the secret as the key.  Send the result back to server, along with client public key.
             *   6. Server uses its private key with client public key, to derive the same secret.  HMAC sign the original challenge,
             *      and verify that the result matches the challenge response that the client sent.  This verifies that the client in
             *      fact has the private key that corresponds to the exposed client public key.
             *   7. The server must confirm that the exposed client public key matches the public key previously set by the client.
             */

            /* 
             *   1. The client checks that CBCryptHostId matches the SSL Cert Subject.
             */
            var hostname = "www.example.com";
            /* This is how we *would* connect to the server.  Commented out for NUnitTest.
            var client = new TcpClient(hostname, 443);
            var sslStream = new SslStream(client.GetStream(),leaveInnerStreamOpen: false);
            sslStream.AuthenticateAsClient(hostname);
             */
            // An exception would have been thrown by now, if the server didn't have a valid cert that matched the hostname.
            /* The server needs to provide the CBCryptHostId.  Lots of times this will be identical to the fqdn of the server,
             * but due to the nature of DNS and CNAME's, and a single DNS name resolving to multiple IP addresses etc, and 
             * NameBasedVirtualHost, and Server Name Indication (SNI), and https proxies (load balancers) with possibly multiple https 
             * hosts authenticating against a single database, as well as x509 Certs Subject having a syntax for multiple hostnames 
             * and wildcards...  The CBCryptHostId does not necessarily always match the server fqdn.
             * 
             * So the server must inform the client with a normalized CBCryptHostId, which is basically a string that must match the 
             * SSL Cert Subject according to the same rules that AuthenticateAsClient uses to match the hostname to Subject.
             * 
             * In this test, obviously the server isn't going to send me any CBCryptHostId.  So I just set it to match the hostname
             * on the following line.
             */
            string CBCryptHostId = hostname.ToLower().Trim(new char[] {'.'});
            /* Now I need to match CBCryptHostId to sslStream.RemoteCertificate.Subject.
             * Unfortunately, I don't yet know how to do that.  Perhaps best to read the mono source code for AuthenticateAsClient()
             * to figure it out.
             * 
             * For now, I am making it a requirement that CBCryptHostId must be the lowercase variant of hostname, which has already
             * been validated by AuthenticateAsClient().
             * 
             * We can allow for server-provided CBCryptHostId later, when we figure out how to handle it.

            var remoteSubject = sslStream.RemoteCertificate.Subject;
            // For example, remoteSubject might be:  "CN=www.example.com, O=Example Inc, L=New York, S=New York, C=US"
            //                                  or:  "CN=*.example.com, OU=Certificate Authority Validated"
            // In this example, I don't need the sslStream anymore, so I'm closing it.  But obviously in real life I would 
            // need to use it for sending/receiving secure data.
            sslStream.Close();
             */


            /* 
             *   2. The client uses CBCrypt.GenerateKeyPair() to convert the password into a keypair.
             */
            AsymmetricCipherKeyPair clientKeyPair = CBCrypt.CBCrypt.GenerateKeyPair(CBCryptHostId: CBCryptHostId, username: "syndrome", password: "kronos");
            // We're going to need to send the public key to the server.
            byte[] clientPublicDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(clientKeyPair.Public).GetDerEncoded();

            /*
             *   2a.  Unit testing
             */
            // Now since this is just a Unit Test, using a hard-coded CBCryptHostId, username, and password, we want to confirm that we
            // have determinstically recreated the same keypair that we've previously generated for testing.  So we check as follows:
            PrivateKeyInfo clientPrivateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(clientKeyPair.Private);
            byte[] clientPrivateDer = clientPrivateInfo.GetDerEncoded();
            string clientPrivateBase64 = Convert.ToBase64String(clientPrivateDer);
            Assert.IsTrue(clientPrivateBase64 == @"MIIB8wIBADCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBIIBBjCCAQICAQEEIAqo5o7QbH4BQhMfctkCYZ9r5HpP3MKYsHTDVeLURVXcoIHaMIHXAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kAQhA2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWAiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE=");
            string clientPublicBase64 = Convert.ToBase64String(clientPublicDer);
            Assert.IsTrue(clientPublicBase64 == @"MIIBKjCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABDaM1UPl14Gq5yM4T4zpl2KPaB9CGiMhjNJv/PmMJC0dh/ayytfoGZ0CuS7EiHLK37Y5rq5Q10FOsK2z6UjYugY=");

            /*
             *   3. The client establishes a connection to the server for login.
             *   4. The server generates its own ECDH keypair (or uses some stored ECDH keypair).
             *      Server sends both the server public key, and a random generated challenge (16 bytes is good) to the client.
             */
            var ServerKeyPairGenerator = new ECKeyPairGenerator("ECDH");
            // strength parameters:  192, 224, 239, 256, 384, 521
            ServerKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
            AsymmetricCipherKeyPair serverKeyPair = ServerKeyPairGenerator.GenerateKeyPair();

            var challenge = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(challenge);
            }
            byte[] serverPublicDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(serverKeyPair.Public).GetDerEncoded();
            // Now send both the challenge and the public key to client.

            /*
             *   5. Client uses its private key with server public key, to generate derived secret.  HMAC sign the challenge using
             *      the secret as the key.  Send the result back to server, along with client public key.
             */
            var serverPublicKeyRegenerated = PublicKeyFactory.CreateKey(serverPublicDer);
            var clientAgreement = new ECDHBasicAgreement();
            clientAgreement.Init(clientKeyPair.Private);
            byte[] sharedSecretGeneratedByClient = clientAgreement.CalculateAgreement(serverPublicKeyRegenerated).ToByteArray();

            byte[] challengeResponse;
            using (var hmac = new System.Security.Cryptography.HMACSHA256(sharedSecretGeneratedByClient))
            {
                challengeResponse = hmac.ComputeHash(challenge);
            }
            // Now send challengeResponse and clientPublicDer to the server.

            /*
             *   6. Server uses its private key with client public key, to derive the same secret.  HMAC sign the original challenge,
             *      and verify that the result matches the challenge response that the client sent.  This verifies that the client in
             *      fact has the private key that corresponds to the exposed client public key.
             */
            var clientPublicKeyRegenerated = PublicKeyFactory.CreateKey(clientPublicDer);
            var serverAgreement = new ECDHBasicAgreement();
            serverAgreement.Init(serverKeyPair.Private);
            byte[] sharedSecretBytesGeneratedByServer = serverAgreement.CalculateAgreement(clientPublicKeyRegenerated).ToByteArray();

            // Unit testing
            string sharedSecretBase64GeneratedByServer = Convert.ToBase64String(sharedSecretBytesGeneratedByServer);
            string sharedSecretBase64GeneratedByClient = Convert.ToBase64String(sharedSecretGeneratedByClient);
            Assert.IsTrue(sharedSecretBase64GeneratedByClient == sharedSecretBase64GeneratedByServer);

            byte[] challengeResponseCheck;
            using (var hmac = new System.Security.Cryptography.HMACSHA256(sharedSecretBytesGeneratedByServer))
            {
                challengeResponseCheck = hmac.ComputeHash(challenge);
            }

            // Verify that the challengeResponse matches challengeResponseCheck.  Otherwise the client auth has failed.
            if (challengeResponse == null)
            {
                // Return false, or throw exception, or something to indicate auth failure
                throw new Exception("challengeResponse failure null");
            }
            if (challengeResponse.Length != challengeResponseCheck.Length)
            {
                // Return false, or throw exception, or something to indicate auth failure
                throw new Exception("challengeResponse failure length");
            }
            for (int i=0; i<challengeResponse.Length; i++)
            {
                if (challengeResponse[i] != challengeResponseCheck[i])
                {
                    // Return false, or throw exception, or something to indicate auth failure
                    throw new Exception("challengeResponse failure value");
                }
            }

            /*
             *   7. The server must confirm that the exposed client public key matches the public key previously set by the client.
             */

            // Now we have verified the challengeResponse, which means the client really has the private key associated to the exposed public key.
            // We only need to check our database (or whatever) to ensure the client public key exposed in this session matches the client public
            // key that the user previously set in a prior session.
            // This is an exercise left to the reader.
        }
    }
}

