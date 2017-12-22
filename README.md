Encrypted is a simple monadic data type that wraps arbitrary data for asymmetric encryption. It provides map and flatMap functions to apply operations on the payload.

# Usage

First you need to generate key pairs for all involved parties:

```scala
import com.github.greywombat.encrypted._

val alice = KeyPair("alice")
val bob = KeyPair("bob")
val eve = KeyPair("eve")
```

Then, you can set up a key store for the public keys of all members and declare one private key as your own:

```scala
implicit val publicKeyStore: PublicKeyStore = KeyStore().addKey(alice).addKey(bob).addKey(eve)
implicit val privateKey: PrivateKey = alice
```

Afterwards you can use it:

```scala
val enc: Encrypted[String] = Encrypted("Secret data")
```

Note that it is not actually encrypted yet, to do

```scala
val enc = Encrypted("Secret data").encrypt
```

To limit access to the data, you can apply a set of client ids:

```scala
val enc = Encrypted("Secret data").restrict(Set("alice", "bob")).encrypt
```

You can access the payload by calling get (optionally with a private key):

```scala
// Some("Secret data")
enc.get

// None
enc.get(eve.privateKey)
```

Encrypted values can be mapped over:

```scala
// Some("Secret data. And more secret data.")
enc.map(_ + ". And more secred data.").get
```

Or, used in a list comprehension:

```scala
val enc2 = for(
    a <- enc;
    b <- Encrypted(". And more secret data.").restrict(Set("alice"))
  ) yield a + b

// Some("Secret data. And more secret data.")
enc2.get

// None
enc2.get(bob)
```

When doing this the resulting encrypted container only allows access for parties that have access to all data that was involved in creating the new data.
