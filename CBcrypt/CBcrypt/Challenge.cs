using System;

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

		/// <summary>
		/// Throws CryptographicException if ObsoleteSharedSecret length != 32
		/// </summary>
		[Obsolete("Used only for backward compatibility with a broken version of CBCrypt")]
		public bool TryObsoleteValidateChallengeResponse(ChallengeResponse response)
		{
			byte[] sharedSecret = this.ServerEphemeralKey.GetObsoleteSharedSecret(response.PublicKeyDerEncoded);
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
