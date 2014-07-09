# CBcrypt #

Next-generation user authentication, beyond bcrypt, scrypt, pbkdf2

## In a Nutshell ##

CBCrypt deterministically generates an asymmetric keypair from servername, username, and password with rate-limiting function applied client-side, before making an authentication attempt to the server. The user's password is kept secret even from the server they're logging into.

Take it as granted, that many different authentication techniques exist in the world (password, public/private keypair, x509 certificate, etc).  Each of these techniques has their own strengths and weaknesses, and none of them is going away anytime soon.  CBcrypt focuses specifically on improving one of those techniques:  Password authentication.

CBcrypt combines publicly known authentication factors (typically username and server id) with secret factors (password), applies a rate-limiting work function such as scrypt or pbkdf2, to deterministically generate a random seed.  This seed is then used in a pseudo-random number generator (prng), and the prng is used as the basis for generating a public/private keypair.  The end result is a deterministically generated keypair, which can only be derived by knowing the user's secret password, and working forward through the rate limiting function.  In this way, a user can authenticate using a password, without ever exposing the password to the server or the network.

As currently implemented, the rate limiting function parameters and the key generation parameters have been selected to require a total approx 200ms-500ms on a modern laptop.

Without CBcrypt, if a server or communication channel is compromised (for example, heartbleed, etc) then the attacker gains the ability to impersonate users, and probably the ability to impersonate them at other servers, where the same password was reused, and all the data on the server is compromised.

With CBcrypt, even if a server or communication channel is compromised (for example, heartbleed, etc) the attacker does not learn users' passwords, and does not gain the ability to impersonate them on other sites.  The attacker doesn't even gain the ability to impersonate them on the *compromised* server.  And if the user's data on the compromised server is encrypted using the user's keypair, then even the users' data is still protected.  (Note: ECDSA can only be used for encryption between two parties; cannot be used for encryption when saving ciphertext for one's self at a later time. If this feature is desired, the workaround is to DER encode the private key, hash it, and use the hash of the private key as an encryption key.  Example code in Unit Test.)

## The Problem ##

Historically, plaintext passwords were stored in a permission restricted backend data stores, until enough real life situations occurred in which attackers were able to bypass the permission restrictions and gain access to those stores.  Then servers started storing non-reversible hashes of passwords (such as MD5) in permission restricted backend data stores, until enough real life situations occurred in which attackers were able to bypass the permission restrictions, and use brute force or rainbow table attacks to compromise user accounts.  Then they started using salting & stretching systems such as crypt, bcrypt, pbkdf2, scrypt or others, to rate-limit brute force attacks against individual users, and ensure stored hashes would be dissimilar even if users had repeated usernames and/or passwords on the same server or different servers.

Real life compromises have forced modern best-practice systems to acknowledge and assume the risk of an attacker accessing the restricted backend datastore.

"But wait," you should be asking, "If we acknowledge the risk of backend datastore compromise, why don't we acknowledge the risk of runtime memory compromise, or communication channel compromise?"

Good question.  But wait, there's more.

Even if you use effective salting/stretching/rate-limiting systems such as bcrypt, scrypt, pbkdf2, you are vulnerable to phishing and phishing-man-in-the-middle attacks.  Let's imagine that Alice normally visits https://foo.com but an attacker tricks her into clicking https://f00.com.  When she enters her username and password, she has given the impostor the ability to impersonate her identity at https://foo.com and anywhere else that she uses the same password.  All the while, her browser is showing green checkmarks, secure lock symbols and good trusted and verified SSL certificates.  The malicious website could even pass-thru all the traffic to the real https://foo.com, or redirect the client browser, so she sees a familiar interface she expects, unaware that she's been attacked.

Users are also vulnerable to password reuse attacks.  If a user has accounts at foo.com and bar.com using the same username and password, then any successful attack against either site effectively compromises the user's identity at *all* sites where she uses the same password.

## The Solution ##

Users should never give their secrets to anyone, not even supposedly trusted and verified secure servers.  So how can a server verify the identity of a user, without knowing their secret?  The answer begs for a solution using asymmetric cryptography.

(See "In a Nutshell" above).  CBCrypt deterministically generates a public/private keypair unique to each specific user, on a specific server, using a specific password.  Any variation of any of these factors results in an entirely different and unrelated keypair.

If a user attempts to login to a malicious site accidentally or because they were tricked by a similar but different name, the malicious server will only gain knowledge of a derived public key.  The attacker will not be able to impersonate the user at any other server, or even on the compromised server, because the attacker has not discovered either the user's private key for connecting to the compromised server, or the user's password that could be used to derive the private key on this or other servers.  The worst attack a malicious server can mount is an expensive brute force attack, attempting to overpower the rate-limiting function and eventually guess a password that recreates the exposed public key.

This also has the advantage that the rate-limiting workfactor can be done by either the client or the server, *or both*.  But there is a tradeoff between these two philosophies.  If the workfactor is done by the client, then low-power clients might take a long time to authenticate, or in order for low-power clients to authenticate in a reasonable amount of time, the workfactor might need to be reduced to the point where it does not effectively prevent large scale brute force attacks mounted by a malicious or compromised server.  If the workfactor is done by the server with high computational and memory resources, then the server can ensure strongly protected data at rest, but does not effectively protect against runtime memory compromise, or phishing or phishing in the middle.

The most secure solution includes a workfactor *both* client-side and server-side.  The client-side workfactor may be limited by low-power client devices, but it provides all the protection possible against malicious server-side runtime compromise and phishing and phishing man in the middle attacks.  The server-side workfactor guarantees at least a minimum standard level of protection against data-at-rest compromise, despite potentially low-powered clients using weak workfactors.

## Implementation Details ##

In the long run, it will be good to abstract this conceptually, formalize a communication protocol that will accommodate server name changes, and negotiation of which crypto protocols to use.  For now, all that is foregone in order to get a useful product implemented for a specific purpose, proof of concept.

Presently, the implementation is as follows:

- CBCrypt.GenerateKeyPair() accepts precisely three arguments. None of which may be null or blank: string CBCryptHostId, string username, string password.
- LowCostSecret is derived by UTF8 encoding to bytes, each argument in order, and SHA256 hashing each argument in order, to create a concatenation of hashes, and then hash the concatenated hashes. The resultant hash should be unique for any unique combination of CBCryptHostID/username/password.
- HighCostSecret is derived by using SCrypt on the LowCostSecret.  Using SCrypt parameters: 16-byte all-zero salt, cost 4096, blockSize 8, parallel 1.
- SeededPRNG is a SHA256 digest random generator, seeded by HighCostSecret.
- Keypair is ECDSA 256, derived from SeededPRNG


## Documentation and API ##

The entire API consists of just one static method:

    AsymmetricCipherKeyPair CBCrypt.GenerateKeyPair(string CBCryptHostId, string username, string password)

Returns the ECDSA-256 keypair derived from the parameters.

For example usage, please see the NUnit Test <https://raw.githubusercontent.com/rahvee/CBcrypt/master/CBcrypt/NUnitTest/Test.cs>

## Download ##

Please use NuGet to add CBCrypt to your project.

If desired, source code is available here: <https://github.com/rahvee/CBcrypt>

## License ##

CBCrypt is distributed under the MIT license.  Details here:  <https://raw.githubusercontent.com/rahvee/CBcrypt/master/LICENSE>

## Support ##

Write to [cbcrypt-dev@conceptblossom.com](mailto://cbcrypt-dev@conceptblossom.com) 