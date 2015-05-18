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
	}
}
