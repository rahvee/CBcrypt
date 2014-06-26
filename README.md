# CBcrypt #

Next-generation user authentication, beyond bcrypt, scrypt, pbkdf2

## In a Nutshell ##

Take it as granted, that many different authentication techniques exist in the world (password, public/private keypair, x509 certificate, 2-factor via SMS or email etc).  Each of these techniques has their own strengths and weaknesses, and none of them is going away anytime soon.  CBcrypt focuses specifically on improving one of those techniques:  Password authentication.

CBcrypt combines publicly known authentication factors (typically username and server id) with secret factors (password), applies a rate-limiting work factor such as scrypt or pbkdf2, to deterministically generate a random seed.  This seed is then used in a pseudo-random number generator (prng), and the prng is used as the basis for generating a public/private keypair.  The end result is a deterministically generated keypair, which can only be derived by knowing the user's secret password, and working forward through the rate limiting function.  In this way, a user can authenticate using a password, without ever exposing the password to the server.

On CBcrypt, if a server is compromised (for example, heartbleed, etc) the attacker only gains knowledge of the users' public keys.  The attacker does NOT gain the ability to impersonate users, because the attacker has not gained their secret passwords or private keys.

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

## How It Works ##

The application programmer designs the app to collect certain input factors which uniquely identify the authentication session.  The parameters may be hard-coded into the client application, or negotiated between the client and server for the authentication session.  Whatever the parameters are, they must remain static from one individual user's authentication session to the next.  For example:

- Server Name
- Server Port
- Username
- Password

The hashes of each factor are chained together, with each successive hash becoming the key for the next hash, creating a pre-workfactor secret, unique hash for the authentication session.

The pre-workfactor secret is then fed through a rate limiting workfactor function.  It is recommended to select a workfactor that results in 100ms to 5sec computation time on the user's hardware.  To make this determination, the application programmer must guess the performance of the expected end user hardware, or provide some mechanism for the end user to select their own.

After applying the workfactor function, you have an essentially random number generated deterministically by all the inputs and rate-limiting function.  This number is used to seed a PRNG, which is then used to generate the Final Keypair.

During an authentication session, the client must provide username and public key to the server.  The server may use either a static or ephemeral keypair.  The server must verify that the user's public key matches a known value for that user, and must also validate that the client posesses the corresponding private key.  In order to authenticate the user, the server must check:

- Confirm that the current session user public key matches the known user public key.
- Confirm that the current session user knows the private key associated to the exposed public key.
  - If using ECDH or similar, this means initializing a DH session with the client public key and the server private key, and then in BouncyCastle terms "GenerateKeyPair" or in .NET ECDiffieHellman terms, "DeriveKeyMaterial."  Generate a random message M, encrypt it to M' using the generated secret, send it to the client, and authenticate the client if it can decrypt and send back message M.  Or an equivalent process.
  - If using RSA or similar, this means generating a secret message M, encrypting it to M' with the client public key, sending it to the client, and expecting the client to decrypt and send back M.  Or an equivalent process.


## Design Considerations ##

- Only the public component of the Final Keypair is to be exposed to the server.
- It is infeasible to discover the private component of the Final Keypair, without first knowing or guessing all the input factors and working forward through the rate-limiting function.
- Different users on the same server will all produce unique Final Keypairs, even if they happen to use the same password.
- An individual user will have dissimilar keys connecting to different servers.

This leaves two problems unresolved:

- Given that the public component of the user's Final Keypair was exposed to the server, a malicious server can mount a brute force forward attack to guess the user's password, in an expensive attempt to overpower the rate limiting function.  This is much better for user security than the current industry standard in which the user's password is communicated to the server to be tested by bcrypt, scrypt, or similar.  It is important for user security, that the user password be changed frequently enough, with sufficient enough complexity, to make the brute force attack prohibitively expensive within the lifetime of the password.
- Given that the server has no knowledge of the password, password complexity is therefore left to the client for enforcement.  Note:  I did not say password complexity is left to the user.  I said it is left to the client.  You may define a complexity requirement on the server and communicate it to the client during a password change attempt.  The policy is only able to be circumvented by sophisticated users who have reverse engineered or hacked up a client specifically for this purpose.  Hopefully these are the same users that desire not to undermine the security of their own user account.

## Salts ##

You may have noticed, that there are no salts anywhere.  This is not strictly true.  First of all, you *could* introduce a salt as one of the input factors.  Second of all, as mentioned, it is recommended to apply a workfactor both clientside and serverside.  It would be natural, serverside, to use bcrypt or scrypt with a server generated random salt.  And third of all, nearly all benefit of salting has already been addressed in a different way.  To qualify this, let's examine the purposes of salting:

- Ensure different hashes will be stored on the server, even if different users have the same password.
- Ensure different hashes will be stored on different servers, even if an individual user has the same username and password on different servers.
- Countermeasure to pre-computed rainbow tables
- Ensure the only way for an attacker to discover any user's password is to first discover the stored hash, and then mount an expensive brute force attack against a specific user on a specific compromised system, attempting to overpower the rate-limiting function.

Even if no salts are used in CBcrypt, all of these requirements are met, except one:  It is possible for an attacker to start computing now, a table of public keys that would correspond to a specific user at a specific server.  This attack is necessarily limited in scope, as it is a targeted attack.

To address this one issue, if you want to introduce a salt, whenever a user changes their password, let the client generate a new salt and send the salt to the server along with the new public key.  The server must store the salt, and provide it to future authentication session attempts against the same user account before future clients can attempt authentication.  This carries implications:

- Some information may be leaked to unauthenticated users, regarding how frequently some individual users change their password.  (An unauthenticated user may request salt for joeuser repeatedly, and it must remain static until joeuser changes his password.)
- If an attacker requests salt for a nonexistent user, the server must emulate a user, in order to prevent leaking information about the existence of a specific username.  The server must store this fake user and salt, and occasionally change its salt, emulating a real user.

Given that the difficulty and complexity of introducing a salt to the system is significant, and that the only benefit is defense against precomputed password guesses for a targeted user on a targeted server...  Given that there are other better ways to deal with this, it is very realistic to go forward without salting in CBcrypt.  If you choose to go forward without salting, it is recommended to enforce a password aging and complexity policy, to minimize the possibility for an attacker to ever brute force guess a targeted user's password.

## Project Status ##

This project is brand new in March 2014.  Basic functionality is present and I believe it's all secure, but it needs community review.  And it would be nice to improve the documentation and extend the functionality - presently it's using Sha256 and ECDH, and should be easily able to plugin different algorithms, but none of the alternatives have been added yet.

## How To Build ##

### Visual Studio ###

In VS 2013, just open the .sln file.  When you build, nuGet should automatically fetch dependent libraries (BouncyCastle, CryptSharp, at the time of this writing.)

### MonoDevelop / Xamarin Studio ###

You should probably add the [MonoDevelop nuGet Addin](https://github.com/mrward/monodevelop-nuget-addin).

Right click each project, and "Restore nuGet Packages."  It should automatically download dependent libraries (BouncyCastle and CryptSharp, at the time of this writing).

## Community ##

Presently, there's just this github project.  And I haven't yet created any "real" mailing list or anything.  I figure if a bunch of people become interested, it will give me motivation to create such a group.  For now, it was just super easy for me to create a simple dumb distribution list.  Anyone may write to [cbcrypt-dev@conceptblossom.com](mailto://cbcrypt-dev@conceptblossom.com) 

If you'd like to receive mail that others post, please just say so, and I'll manually add you to the group.  And as soon as the numbers become annoying to me, we'll create a normal internet discussion list.