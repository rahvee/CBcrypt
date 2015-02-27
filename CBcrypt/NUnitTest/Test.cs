using NUnit.Framework;
using System;
using Org.CBCrypt;
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
using Newtonsoft.Json;

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
		public void Test_CBCrypt_Server_Client_Handshake()
		{
			/* Imagine a client wants to authenticate to a server, without exposing the user's password to the server.
			 * The sequence of things that must happen are as follows:
			 *   0. The client connects to server via SslStream
			 *   1. The server generates new Challenge, which contains an ephemeral keypair, ChallengeBytes, and CBCryptHostId
			 *      Server sends Challenge to client.
			 *   2. The client checks that CBCryptHostId matches the SSL Cert Subject.
			 *   3. The client generates clientKey from CBCryptHostId, username, and password
			 *   4. The client generates ChallengeResponse from clientKey and serverChallengeDeserialized. Sends ChallengeResponse to server
			 *   5. The server does TryValidateChallengeResponse, to ensure the client knows the client's private key
			 *   6. The server stores or looks up ChallengeResponse.PublicKeyDerEncoded, to confirm this user matches a known user
			 */

			// We're going to need this later, just because I'm choosing to use Newtonsoft.Json for test serialization.
			var jsonSettings = new JsonSerializerSettings() { TypeNameHandling = TypeNameHandling.All, Formatting = Formatting.Indented };

			/*
			 *   0. The client connects to server via SslStream
			 */
			string hostname = "www.example.com";
			/* This is how the client *would* connect to the server.  Commented out for NUnitTest.
			 * 
			 * var client = new TcpClient(hostname, 443);
			 * var sslStream = new SslStream(client.GetStream(),leaveInnerStreamOpen: false);
			 * sslStream.AuthenticateAsClient(hostname);
			 */

			/*
			 *   1. The server generates new Challenge, which contains an ephemeral keypair, ChallengeBytes, and CBCryptHostId
			 *      Server sends Challenge to client.
			 * 
			 *   I am not writing how to make the server listen and accept client and do AuthenticateAsServer.  You can look it up.
			 *   Imagine this is a server, and we just accepted a client on SslStream, and have completed AuthenticateAsServer.
			 */
			// TODO: ISSUE #1 CBCryptHostId must match DNS name exactly https://github.com/rahvee/CBcrypt/issues/1
			var serverChallenge = new Challenge(hostname);
			/* Now serialize serverChallenge, and send to client. Beware! Challenge contains the private key, marked as private.
			 * Make sure you look at your serialization stream, and ensure your serializer does not serialize the private key.
			 * Generally speaking, serializers honor this convention and only serialize public fields/properties, but the behavior
			 * is configurable, so heed this warning.
			 * The stream should contain properties "ChallengeBytes" , "CBCryptHostId" , "ServerPublicKeyDerEncoded"
			 * The stream should NOT contain "ServerEphemeralKey"
			 */
			string serverChallengeString = JsonConvert.SerializeObject(serverChallenge, jsonSettings);
			byte[] serverChallengeBytes = System.Text.Encoding.UTF8.GetBytes(serverChallengeString);
			// sslStream.Write(serverChallengeBytes, 0, serverChallengeBytes.Length);

			/* 
			 *   2. The client checks that CBCryptHostId matches the SSL Cert Subject.
			 */
			string serverChallengeStringAgain = System.Text.Encoding.UTF8.GetString(serverChallengeBytes);
			var serverChallengeDeserialized = (Challenge)JsonConvert.DeserializeObject(serverChallengeStringAgain, jsonSettings);
			// TODO: ISSUE #1 CBCryptHostId must match DNS name exactly https://github.com/rahvee/CBcrypt/issues/1
			if (hostname != serverChallengeDeserialized.CBCryptHostId) {
				// If the user has already been prompted and accepted an invalid SSL cert, just continue as if 
				// hostname and CBCryptHostIdSentToClient actually matched.
				// Otherwise, prompt user about mismatching CBCryptHostId, which should exactly match the DNS name of the server.
			}

			/* 
			 *   3. The client generates clientKey from CBCryptHostId, username, and password, or uses a stored HighCostSecret
			 */
			// If the user is allowed to "save password" in their GUI, you should use CBCrypt.GenerateHighCostSecret to fetch a byte
			// array, and store those bytes encrypted on disk. I might suggest using System.Security.Cryptography.ProtectedData.
			// In this way, the password is stored as safely as it possibly can be - salted, stretched, hashed, and additionally 
			// encrypted - Later, you can generate new CBCryptKey(HighCostSecret)
			var clientKey = new CBCryptKey(CBCryptHostId: serverChallengeDeserialized.CBCryptHostId, username: "syndrome", password: "kronos");

			/*
			 *   3a.  Unit testing
			 */
			// Now since this is just a Unit Test, using a hard-coded CBCryptHostId, username, and password, we want to confirm that we
			// have determinstically recreated the same keypair that we've previously generated for testing.  So we check as follows:
			byte[] clientPrivateDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(clientKey.Key.Private).GetDerEncoded();
			string clientPrivateBase64 = Convert.ToBase64String(clientPrivateDer);
			Assert.IsTrue(clientPrivateBase64 == @"MIIB8wIBADCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBIIBBjCCAQICAQEEIAqo5o7QbH4BQhMfctkCYZ9r5HpP3MKYsHTDVeLURVXcoIHaMIHXAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kAQhA2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWAiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE=");
			byte[] clientPublicDer = clientKey.GetPublicKeyDerEncoded();
			string clientPublicBase64 = Convert.ToBase64String(clientPublicDer);
			Assert.IsTrue(clientPublicBase64 == @"MIIBKjCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABDaM1UPl14Gq5yM4T4zpl2KPaB9CGiMhjNJv/PmMJC0dh/ayytfoGZ0CuS7EiHLK37Y5rq5Q10FOsK2z6UjYugY=");

			/*
			 *   4. The client generates ChallengeResponse from clientKey and serverChallengeDeserialized. Sends ChallengeResponse to server
			 */
			var challengeResponse = new ChallengeResponse(clientKey, serverChallengeDeserialized);
			string challengeResponseString = JsonConvert.SerializeObject(challengeResponse, jsonSettings);
			byte[] challengeResponseBytes = System.Text.Encoding.UTF8.GetBytes(challengeResponseString);
			// sslStream.Write(challengeResponseBytes, 0, challengeResponseBytes.Length);

			/*
			 *   5. The server does TryValidateChallengeResponse, to ensure the client knows the client's private key
			 */
			string challengeResponseStringAgain = System.Text.Encoding.UTF8.GetString(challengeResponseBytes);
			var challengeResponseDeserialized = (ChallengeResponse)JsonConvert.DeserializeObject(challengeResponseStringAgain, jsonSettings);
			Assert.IsTrue(serverChallenge.TryValidateChallengeResponse(challengeResponseDeserialized), "Failed TryValidateChallengeResponse");

			/*
			 *   6. The server stores or looks up ChallengeResponse.PublicKeyDerEncoded, to confirm this user matches a known user
			 */

			// Now we have verified the challengeResponse, which means the client really has the private key associated to the exposed public key.
			// We only need to check our database (or whatever) to ensure the client public key exposed in this session matches the client public
			// key that the user previously set in a prior session.
			// This is an exercise left to the reader.
		}
	}
}

