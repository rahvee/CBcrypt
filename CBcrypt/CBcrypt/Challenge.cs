using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math;

namespace Org.CBCrypt
{
	public class Challenge
	{
		private const int ChallengeSize = 32;
		private const int tempKeySize = 32;
		private CBCryptKey ServerEphemeralKey;
		public byte[] ChallengeBytes { get; set; }
		public string CBCryptHostId { get; set; }
		public byte[] ServerPublicKeyDerEncoded { get; set; }

		public Challenge()
		{
			// Empty constructor is requirement for deserialization
		}
		public Challenge(string CBCryptHostId)
		{
			this.CBCryptHostId = CBCryptHostId;
			this.ChallengeBytes = new byte[ChallengeSize];
			// The easiest way for me to generate an ephemeral key is to feed random bytes into CBCrypt.GenerateKeyPair
			var tempKey = new byte[tempKeySize];
			using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider()) {
				rng.GetBytes(this.ChallengeBytes);
				rng.GetBytes(tempKey);
			}
			this.ServerEphemeralKey = new CBCryptKey(tempKey);
			this.ServerPublicKeyDerEncoded = this.ServerEphemeralKey.GetPublicKeyDerEncoded();
		}

		public byte[] GetServerPublicDer()
		{
			return this.ServerEphemeralKey.GetPublicKeyDerEncoded();
		}
		public static byte[] GenerateChallengeResponseBytes(byte[] challenge, byte[] sharedSecret)
		{
			using (var hmac = new System.Security.Cryptography.HMACSHA256(sharedSecret)) {
				return hmac.ComputeHash(challenge);
			}
		}
		public bool TryValidateChallengeResponse(ChallengeResponse response)
		{
			byte[] sharedSecret = this.ServerEphemeralKey.GetSharedSecret(response.PublicKeyDerEncoded);
			byte[] challengeResponseCheck = GenerateChallengeResponseBytes(this.ChallengeBytes, sharedSecret);

			// Verify that the challengeResponse matches challengeResponseCheck.  Otherwise the client auth has failed.
			if (response.ChallengeResponseBytes == null || (response.ChallengeResponseBytes.Length != challengeResponseCheck.Length)) {
				return false;
			}
			for (int i = 0; i < challengeResponseCheck.Length; i++) {
				if (response.ChallengeResponseBytes[i] != challengeResponseCheck[i]) {
					return false;
				}
			}
			return true;
		}
	}
}
