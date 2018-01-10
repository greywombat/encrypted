package com.github.greywombat.encrypted

import org.abstractj.kalium
import org.abstractj.kalium.NaCl
import org.abstractj.kalium.crypto.{Random, SealedBox, SecretBox}

sealed trait Encrypted[+A] {
  /**
    * Marshaller to serialise and unserialise objects (and functions).
    *
    * @return
    */
  protected def marshaller: Marshaller = new Marshaller {

    import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

    override def marshall[A](obj: A): Array[Byte] = {
      val bo = new ByteArrayOutputStream()
      new ObjectOutputStream(bo).writeObject(obj)
      bo.toByteArray
    }

    override def unmarshall[A](bytes: Array[Byte]): A = {
      new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject().asInstanceOf[A]
    }
  }


  /**
    * Determines if agent is granted access on the encrypted element.
    *
    * @param id ID of the agent
    * @return
    */
  def allowed(id: String): Boolean

  /**
    * Restrict access to the listed agents.
    *
    * @param allowedIds IDs of the agents to be granted access.
    */
  def restrict(allowedIds: Set[String]): Encrypted[A] = new AppendedRestrict[A](this, allowedIds)

  /**
    * Encrypt the data with keys from the provided keystore.
    *
    * @param publicKeyStore
    */
  def encrypt(implicit privateKey: PrivateKey, publicKeyStore: PublicKeyStore): Encrypted[A] =
    get match {
      case Some(plain) => new Public[A](plain).encrypt
      case None => this
    }

  /**
    * Decrypts the content
    *
    * @param privateKey
    * @return The content if was successfully decrypted.
    */
  def get(implicit privateKey: PrivateKey): Option[A]

  /**
    * Binds a function to the instance.
    *
    * @param f
    * @param privateKey
    * @tparam B
    * @return A new Encrypted, carrying the result of f and the union of access permissions.
    */
  def flatMap[B](f: (A) => Encrypted[B])(implicit privateKey: PrivateKey): Encrypted[B] =
    new AppendedBind(this, f)

  /**
    * Maps a function over the instance.
    *
    * @param f
    * @tparam B
    * @return A new Encrypted, with the result of f.
    */
  def map[B](f: (A) => B): Encrypted[B] = new AppendedMap(this, f)

  def canEqual(a: Any) = a.isInstanceOf[Encrypted[A]]

  override def equals(that: Any): Boolean =
    that match {
      case that: Encrypted[A] => that.canEqual(this) && this.hashCode == that.hashCode
      case _ => false
    }
}

object Encrypted {
  /**
    * Create a new Encrypted from some payload
    *
    * @param content The content (payload).
    * @param privateKey
    * @param publicKeyStore
    * @tparam A Type of the payload.
    * @return
    */
  def apply[A](content: A)(implicit privateKey: PrivateKey, publicKeyStore: PublicKeyStore) =
    new Public(content)
}

sealed trait PrivateKey {
  def keyId: String

  def privateKey: kalium.keys.PrivateKey

  def publicKey: kalium.keys.PublicKey
}

/**
  * A key pair consists of a private and a public key for asymmetric encryption of data.
  *
  * @param id Identifier of the owner (client) of the key
  * @param publicKey
  * @param privateKey
  */
class KeyPair(id: String, override val publicKey: kalium.keys.PublicKey, override val privateKey: kalium.keys.PrivateKey) extends PrivateKey {
  def keyId = id
}

object KeyPair {
  def apply(id: String, keyPair: kalium.keys.KeyPair): KeyPair = new KeyPair(id, keyPair.getPublicKey, keyPair.getPrivateKey)

  def apply(id: String, publicKey: Array[Byte], privateKey: Array[Byte]): KeyPair =
    new KeyPair(id, new kalium.keys.PublicKey(publicKey), new kalium.keys.PrivateKey(privateKey))

  /**
    * Generate a new keypair for client with a given id.
    *
    * @param id Identifier of the client.
    * @return
    */
  def apply(id: String): KeyPair = apply(id, new kalium.keys.KeyPair())
}

sealed trait PublicKeyStore {
  def get(keyId: String): Option[kalium.keys.PublicKey]

  def ids: Set[String]
}

/**
  * A keystore is used to store public keys for encryption.
  *
  * @param keyMap
  */
class KeyStore(keyMap: Map[String, kalium.keys.PublicKey]) extends PublicKeyStore {
  override def get(keyId: String) = keyMap.get(keyId)

  override def ids = keyMap.keySet

  def addKey(keys: KeyPair): KeyStore = new KeyStore(keyMap + (keys.keyId -> keys.publicKey))

  def addKey(id: String, key: kalium.keys.PublicKey): KeyStore = new KeyStore(keyMap + (id -> key))
}

object KeyStore {
  def apply(keyMap: Map[String, kalium.keys.PublicKey]) = new KeyStore(keyMap)

  /**
    * Obtain a new, empty keystore.
    *
    * @return
    */
  def apply() = new KeyStore(Map.empty[String, kalium.keys.PublicKey])
}

sealed trait Marshaller {
  def marshall[A](obj: A): Array[Byte]

  def unmarshall[A](bytes: Array[Byte]): A
}

class Public[A](content: A) extends Encrypted[A] {

  override def allowed(id: String) = true

  override def encrypt(implicit privateKey: PrivateKey, publicKeyStore: PublicKeyStore): Encrypted[A] = {
    if (publicKeyStore == null) return this
    val nonce = new Random().randomBytes(NaCl.Sodium.CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES)
    val key = new Random().randomBytes(NaCl.Sodium.CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES)
    val plaintext = marshaller.marshall[A](content)
    val cyphertext = new SecretBox(key).encrypt(nonce, plaintext)
    val encryptedKeys = publicKeyStore.ids.filter(allowed).map { id =>
      val publicKey = publicKeyStore.get(id).get
      val encryptedKey = new SealedBox(publicKey.toBytes).encrypt(key)
      (id -> encryptedKey)
    }.toMap
    new EncryptedPlaintext[A](cyphertext, encryptedKeys, nonce)
  }

  override def get(implicit privateKey: PrivateKey) = Some(content)

  override def map[B](f: (A) => B): Encrypted[B] = new Public[B](f(content))
}

class EncryptedPlaintext[A](cyphertext: Array[Byte], encryptedKeys: Map[String, Array[Byte]], nonce: Array[Byte])
                           (implicit privateKey: PrivateKey, publicKeyStore: PublicKeyStore) extends Encrypted[A] {

  override def allowed(id: String): Boolean = encryptedKeys.keySet.contains(id)

  override def get(implicit privateKey: PrivateKey): Option[A] = {
    if (privateKey == null) return None
    encryptedKeys.get(privateKey.keyId).map { encryptedKey =>
      val key = new SealedBox(privateKey.publicKey.toBytes, privateKey.privateKey.toBytes).decrypt(encryptedKey)
      val payload = new SecretBox(key).decrypt(nonce, cyphertext)
      marshaller.unmarshall[A](payload)
    }
  }
}

class AppendedMap[A, B](prev: Encrypted[A], f: (A) => B) extends Encrypted[B] {
  override def allowed(id: String) = prev.allowed(id)

  override def get(implicit privateKey: PrivateKey): Option[B] = prev.get.map(f)
}

class AppendedBind[A, B](prev: Encrypted[A], f: (A) => Encrypted[B])
                        (implicit privateKey: PrivateKey) extends Encrypted[B] {
  override def allowed(id: String) = prev.allowed(id) && (prev.get match {
    case Some(content) => f(content).allowed(id)
    case None => true
  })

  override def get(implicit privateKey: PrivateKey) = prev.get.flatMap(f(_).get)
}

class AppendedRestrict[A](prev: Encrypted[A], allowedIds: Set[String]) extends Encrypted[A] {
  override def allowed(id: String) = allowedIds.contains(id) && prev.allowed(id)

  override def get(implicit privateKey: PrivateKey) = if (allowed(privateKey.keyId)) prev.get else None
}
