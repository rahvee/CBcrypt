using System;

namespace Org.CBCrypt
{
	public class ChallengeResponse
	{
		public byte[] PublicKeyDerEncoded { get; set; }
		public byte[] ChallengeResponseBytes { get; set; }

		public ChallengeResponse()
		{
			// Empty constructor is requirement for deserialization
		}
		public ChallengeResponse(CBCryptKey clientKey, Challenge ChallengeFromServer)
		{
			this.PublicKeyDerEncoded = clientKey.GetPublicKeyDerEncoded();
			byte[] sharedSecret = clientKey.GetSharedSecret(ChallengeFromServer.ServerPublicKeyDerEncoded);
			this.ChallengeResponseBytes = Challenge.GenerateChallengeResponseBytes(ChallengeFromServer.ChallengeBytes,sharedSecret);
		}

		/// <summary>
		/// GetObsoleteChallengeResponse exists solely for backward compatibility, for clients to connect to servers running
		/// CBCrypt 1.0.5.0 or lower.
		/// </summary>
		[Obsolete]
		public static ChallengeResponse GetObsoleteChallengeResponse(CBCryptKey clientKey, Challenge challengeFromServer)
		{
			var response = new ChallengeResponse();
			response.PublicKeyDerEncoded = clientKey.GetPublicKeyDerEncoded();
			byte[] obsoleteSharedSecret = clientKey.GetObsoleteSharedSecret(challengeFromServer.ServerPublicKeyDerEncoded);
			response.ChallengeResponseBytes = Challenge.GenerateChallengeResponseBytes(challengeFromServer.ChallengeBytes, obsoleteSharedSecret);
			return response;
		}
	}
}
