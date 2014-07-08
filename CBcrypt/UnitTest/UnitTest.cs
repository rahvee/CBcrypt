using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CBCrypt;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;

namespace UnitTest
{
    [TestClass]
    public class UnitTest
    {
        [TestMethod]
        public void Test_CBCrypt_GenerateKeyPair()
        {
            // Pretend a client deterministically generates a keypair to login to server, derived from ServerID, username, password.

            AsymmetricCipherKeyPair keyPair = CBCrypt.CBCrypt.GenerateKeyPair("www.example.com", "syndrome", "kronos");

            // Now verify that it's truly deterministic.  (Compare against my precomputed hard-coded expected result)
            PrivateKeyInfo privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            byte[] privateDer = privateInfo.GetDerEncoded();
            string privateBase64 = Convert.ToBase64String(privateDer);
            Assert.IsTrue(privateBase64 == @"MIIB8wIBADCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBIIBBjCCAQICAQEEIAqo5o7QbH4BQhMfctkCYZ9r5HpP3MKYsHTDVeLURVXcoIHaMIHXAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kAQhA2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWAiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE=");

            byte[] publicDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();
            string publicBase64 = Convert.ToBase64String(publicDer);
            Assert.IsTrue(publicBase64 == @"MIIBKjCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABDaM1UPl14Gq5yM4T4zpl2KPaB9CGiMhjNJv/PmMJC0dh/ayytfoGZ0CuS7EiHLK37Y5rq5Q10FOsK2z6UjYugY=");

            // Now pretend I want to authenticate against some server. The server generates random bytes and sends to client
            var challenge = new byte[16];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(challenge);
            }

            // The client signs the challenge

            /* Possibilities are:
             * "RSA", "MD2withRSA", "MD4withRSA", "MD5withRSA", "SHA-1withRSA", "SHA-224withRSA", "SHA-256withRSA", 
             * "SHA-384withRSA", "SHA-512withRSA", "RIPEMD128withRSA", "RIPEMD160withRSA", "RIPEMD256withRSA", "RAWRSASSA-PSS", 
             * "PSSwithRSA", "SHA-1withRSAandMGF1", "SHA-224withRSAandMGF1", "SHA-256withRSAandMGF1", "SHA-384withRSAandMGF1", 
             * "SHA-512withRSAandMGF1", "NONEwithDSA", "SHA-1withDSA", "SHA-224withDSA", "SHA-256withDSA", "SHA-384withDSA", 
             * "SHA-512withDSA", "NONEwithECDSA", "SHA-1withECDSA", "SHA-224withECDSA", "SHA-256withECDSA", "SHA-384withECDSA", 
             * "SHA-512withECDSA", "RIPEMD160withECDSA", "SHA1WITHECNR", "SHA224WITHECNR", "SHA256WITHECNR", "SHA384WITHECNR", 
             * "SHA512WITHECNR", "GOST3410", "ECGOST3410", "SHA1WITHRSA/ISO9796-2", "MD5WITHRSA/ISO9796-2", "RIPEMD160WITHRSA/ISO9796-2"
             */
            ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");

            signer.Init(forSigning: true, parameters: keyPair.Private);
            signer.BlockUpdate(challenge, 0, challenge.Length);
            byte[] signature = signer.GenerateSignature();

            // The client sends both the signature, and publicBase64 (or publicDer) to the server
            // The server must construct the client's public key
            ISigner verifier = SignerUtilities.GetSigner("SHA-256withECDSA");
            verifier.Init(forSigning: false, parameters: PublicKeyFactory.CreateKey(publicDer));
            verifier.BlockUpdate(challenge, 0, challenge.Length);
            Assert.IsTrue( verifier.VerifySignature(signature) );
        }
    }
}
