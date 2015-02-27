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
	public class CBCryptKey
	{
		public AsymmetricCipherKeyPair Key { get; set; }

		public CBCryptKey(string CBCryptHostId, string username, string password)
		{
			this.Key = CBCrypt.GenerateKeyPair(CBCryptHostId, username, password);
		}
		public CBCryptKey(byte[] HighCostSecret)
		{
			this.Key = CBCrypt.GenerateKeyPair(HighCostSecret);
		}
		public CBCryptKey(AsymmetricCipherKeyPair Key)
		{
			this.Key = Key;
		}

		public static byte[] GetPublicKeyDerEncoded(AsymmetricCipherKeyPair Key)
		{
			return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Key.Public).GetDerEncoded();
		}
		public static byte[] GetSharedSecret(AsymmetricCipherKeyPair localKeyWithPrivate, byte[] remotePublicKeyDerEncoded)
		{
			var remotePublicKey = PublicKeyFactory.CreateKey(remotePublicKeyDerEncoded);
			var agreement = new ECDHBasicAgreement();
			agreement.Init(localKeyWithPrivate.Private);
			return agreement.CalculateAgreement(remotePublicKey).ToByteArray();
		}

		public byte[] GetPublicKeyDerEncoded()
		{
			return GetPublicKeyDerEncoded(this.Key);
		}
		public byte[] GetSharedSecret(byte[] remotePublicKeyDerEncoded)
		{
			return GetSharedSecret(this.Key, remotePublicKeyDerEncoded);
		}
	}
}
