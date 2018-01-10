package com.github.greywombat.encrypted

import org.scalatest.{Matchers, PropSpec}
import org.scalatest.prop.TableDrivenPropertyChecks

class EncryptedSpec extends PropSpec with TableDrivenPropertyChecks with Matchers {

  val keys = Map(
    "alice" -> KeyPair("alice"),
    "bob" -> KeyPair("bob"),
    "carol" -> KeyPair("carol"),
    "eve" -> KeyPair("eve")
  )

  implicit val privateKey: PrivateKey = keys.get("alice").get

  implicit val publicKeyStore: PublicKeyStore = new KeyStore(keys.mapValues(_.publicKey))

  val dataset = Table(
    ("payload", "encypted"),
    ("public", Encrypted("public")),
    ("encrypted", Encrypted("encrypted").encrypt),
    ("restricted", Encrypted("restricted").restrict(Set("alice", "bob"))),
    ("mapAppended", Encrypted("").map(_ + "mapAppended")),
    ("bindAppended", Encrypted("").flatMap(_ => Encrypted("bindAppended")))
  )

  property("should yield payload") {
    forAll(dataset) { (payload, encrypted) =>
      encrypted.get should be(Some(payload))
    }
  }

  property("should deny access when permission restricted") {
    forAll(dataset) { (_, encrypted) =>
      encrypted.restrict(Set("alice")).get(keys.get("eve").get) should be(None)
    }
  }

  property("should decrypt encrypted data") {
    forAll(dataset) { (payload, encrypted) =>
      encrypted.encrypt.get should be(Some(payload))
    }
  }

  property("should be combinable") {
    forAll(dataset) { (payloadA, encryptedA) =>
      forAll(dataset) { (payloadB, encryptedB) =>
        (for (a <- encryptedA;
              b <- encryptedB) yield a + b).get should be(Some(payloadA + payloadB))
      }
    }
  }

  property("should restrict access when combined") {
    forAll(dataset) { (_, encrypted) =>
      val combined = for (a <- encrypted;
                          _ <- Encrypted("empty").restrict(Set("bob"))) yield a
      combined.allowed("alice") should be(false)
      combined.allowed("bob") should be(true)
      combined.allowed("carol") should be(false)
    }
  }

  property("should allow application of map function") {
    forAll(dataset) { (payload, encrypted) =>
      encrypted.map(_.substring(1) + "extra").get should be(Some(payload.substring(1) + "extra"))
    }
  }

  property("should have flatMap obeying left identity law") {
    def testFun(n: Int) = Encrypted(n * 2)

    // identity of content
    Encrypted(10).flatMap(testFun).get shouldEqual testFun(10).get
    // identity of access rights
    keys.keySet.filter(Encrypted(10).flatMap(testFun).allowed(_)) shouldEqual keys.keySet.filter(testFun(10).allowed(_))
  }

  property("should have flatMap obeying right identity law") {
    forAll(dataset) { (_, m) =>
      // identity of content
      m.flatMap(Encrypted.apply[String]).get shouldEqual m.get
      // identity of access rights
      keys.keySet.filter(m.flatMap(Encrypted.apply[String]).allowed(_)) shouldEqual keys.keySet.filter(m.allowed(_))
    }
  }

  property("should have associative flatMap function") {
    def f(str: String) = Encrypted[String](str.reverse)

    def g(str: String) = Encrypted[Int](str.length)

    forAll(dataset) { (_, m) =>
      // associativity for content
      m.flatMap(f).flatMap(g).get shouldEqual m.flatMap(x => f(x).flatMap(g)).get
      // associativity for access rights
      keys.keySet.filter(m.flatMap(f).flatMap(g).allowed(_)) shouldEqual keys.keySet.filter(m.flatMap(x => f(x).flatMap(g)).allowed(_))
    }
  }
}
