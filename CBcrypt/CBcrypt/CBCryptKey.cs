using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Agreement;

namespace Org.CBCrypt
{
	public class CBCryptKey
	{
		[Obsolete("Use AsymmetricKey and SymmetricKey Instead")]
		public AsymmetricCipherKeyPair Key { get { return AsymmetricKey; } set { AsymmetricKey = value; } }

		public AsymmetricCipherKeyPair AsymmetricKey { get; set; }
		public byte[] SymmetricKey { get; set; }

		public CBCryptKey(string CBCryptHostId, string username, string password)
		{
			byte[] highCostSecret = CBCrypt.GenerateHighCostSecret(CBCryptHostId, username, password);
			GenerateKeys(highCostSecret);
		}
		public CBCryptKey(byte[] highCostSecret)
		{
			GenerateKeys(highCostSecret);
		}

		private void GenerateKeys(byte[] highCostSecret)
		{
			SecureRandom seededPRNG = CBCrypt.GetSeededDigestRandomGenerator(highCostSecret);
			this.AsymmetricKey = CBCrypt.GenerateKeyPair(seededPRNG);
			this.SymmetricKey = new byte[32];
			seededPRNG.NextBytes(this.SymmetricKey);
		}

		public static byte[] GetPublicKeyDerEncoded(AsymmetricCipherKeyPair AsymmetricKey)
		{
			return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AsymmetricKey.Public).GetDerEncoded();
		}
		public static byte[] GetSharedSecret(AsymmetricCipherKeyPair localKeyWithPrivate, byte[] remotePublicKeyDerEncoded)
		{
			var remotePublicKey = PublicKeyFactory.CreateKey(remotePublicKeyDerEncoded);
			var agreement = new ECDHBasicAgreement();
			agreement.Init(localKeyWithPrivate.Private);
			using (var sha = SHA256.Create()) {
				// CalculateAgreement returns a BigInteger, whose length is variable, and bits are not whitened.
				// So hash it.
				return sha.ComputeHash(agreement.CalculateAgreement(remotePublicKey).ToByteArray());
			}
		}
		/// <summary>
		/// Sometimes returns number of bytes != 32
		/// </summary>
		[Obsolete("Used only for backward compatibility with a broken version of CBCrypt")]
		public static byte[] GetObsoleteSharedSecret(AsymmetricCipherKeyPair localKeyWithPrivate, byte[] remotePublicKeyDerEncoded)
		{
			var remotePublicKey = PublicKeyFactory.CreateKey(remotePublicKeyDerEncoded);
			var agreement = new ECDHBasicAgreement();
			agreement.Init(localKeyWithPrivate.Private);
			return agreement.CalculateAgreement(remotePublicKey).ToByteArray();
		}

		public byte[] GetPublicKeyDerEncoded()
		{
			return GetPublicKeyDerEncoded(AsymmetricKey);
		}
		public byte[] GetSharedSecret(byte[] remotePublicKeyDerEncoded)
		{
			return GetSharedSecret(AsymmetricKey, remotePublicKeyDerEncoded);
		}
		/// <summary>
		/// Sometimes returns number of bytes != 32
		/// </summary>
		[Obsolete("Used only for backward compatibility with a broken version of CBCrypt")]
		public byte[] GetObsoleteSharedSecret(byte[] remotePublicKeyDerEncoded)
		{
			return GetObsoleteSharedSecret(AsymmetricKey, remotePublicKeyDerEncoded);
		}

		~CBCryptKey ()
		{
			// Although this finalizer will in many situations be insufficient, I'll still do what I can.
			// For example, how about sterilizing the HighCostSecret, or the AsymmetricKey, or anything else?
			var bytes = SymmetricKey;
			if (bytes != null) {
				Array.Clear(bytes, 0, bytes.Length);
			}
		}
	}
}
