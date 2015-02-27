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
