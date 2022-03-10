import UIKit
import CryptoKit
var greeting = "Hello, playground"
// Copyright (c) 2020 Razeware LLC
// For full license & permission details, see LICENSE.markdown.

import UIKit


func getData(for item: String, of type: String) -> Data {
  let filePath = Bundle.main.path(forResource: item, ofType: type)!
  return FileManager.default.contents(atPath: filePath)!
}
//: ## Hashing data
//: ### Hashable Protocol
func hashItem(item: String) -> Int {
  var hasher = Hasher()
  item.hash(into: &hasher)
  return hasher.finalize()
}
let hashValue = hashItem(item: "the quick brown fox")
//: ### Cryptographic Hashing
let data = getData(for: "Baby", of: "png")
UIImage(data: data)

// Create a digest of `data`:
let digest = SHA256.hash(data: data)

// Dumbledore sends`data` and `digest` to Harry,
// who hashes `data` and checks that digests match.
let receivedDataDigest = SHA256.hash(data: data)
if digest == receivedDataDigest {
  print("Data received == data sent.")
}

// Get String representation of `digest`:
String(describing: digest)

// Small change in `data` produces completely different digest:
String(describing: SHA256.hash(data: "Harry is a horcrux".data(using: .utf8)!))
String(describing: SHA256.hash(data: "Harry's a horcrux".data(using: .utf8)!))
//: ## HMAC: Hash-based Message Authentication Code
//: Use a symmetric cryptographic key when creating the digest
//: so the receiver knows it’s from you, or a server can check
//: that you’re authorized to upload files.
// Create a 256-bit symmetric key
let key256 = SymmetricKey(size: .bits256)
// Create a keyed digest of data
let sha512MAC = HMAC<SHA512>.authenticationCode(
  for: data, using: key256)
String(describing: sha512MAC)
// Convert signature to Data
let authenticationCodeData = Data(sha512MAC)
// Dumbledore sends data and signature to Harry, who checks the signature:
if HMAC<SHA512>.isValidAuthenticationCode(authenticationCodeData,
   authenticating: data, using: key256) {
    print("The message authentication code is validating the data: \(data))")
  UIImage(data: data)
}
else { print("not valid") }
//: ## Authenticated Encryption
// Create a sealed box with the encrypted data
let sealedBoxData = try! ChaChaPoly.seal(data, using: key256).combined
// Harry receives sealed box data, then extracts the sealed box
let sealedBox = try! ChaChaPoly.SealedBox(combined: sealedBoxData)
// Harry decrypts data with the same key
let decryptedData = try! ChaChaPoly.open(sealedBox, using: key256)

// What else is in the box?
sealedBox.nonce  // 12 bytes
sealedBox.tag  // 16 bytes
// encryptedData isn't an image
let encryptedData = sealedBox.ciphertext
UIImage(data: encryptedData)
UIImage(data: decryptedData)
//: ## Public-Key Cryptography
// Dumbledore wants to send the horcrux image to Harry.
// He signs it so Harry can verify it's from him.
let albusSigningPrivateKey = Curve25519.Signing.PrivateKey()
let albusSigningPublicKeyData =
  albusSigningPrivateKey.publicKey.rawRepresentation
// Dumbledore publishes `albusSigningPublicKeyData`.
// Dumbledore signs `data` (or `digest`) with his private key.
let signatureForData = try! albusSigningPrivateKey.signature(
  for: data)
// Signing a digest of the data is faster:
let digest512 = SHA512.hash(data: data)
let signatureForDigest = try! albusSigningPrivateKey.signature(
  for: Data(digest512))
// Harry verifies signatures with key created from
// albusSigningPublicKeyData.
let publicKey = try! Curve25519.Signing.PublicKey(
  rawRepresentation: albusSigningPublicKeyData)
if publicKey.isValidSignature(signatureForData, for: data) {
  print("Dumbledore sent this data.")
}
if publicKey.isValidSignature(signatureForDigest,
  for: Data(digest512)) {
  print("Data received == data sent.")
  UIImage(data: data)
}
//: ## Shared secret / Key agreement
// Dumbledore and Harry create private and public keys for
// key agreement, and publish the public keys.
let albusPrivateKey = Curve25519.KeyAgreement.PrivateKey()
let albusPublicKeyData = albusPrivateKey.publicKey.rawRepresentation
let harryPrivateKey = Curve25519.KeyAgreement.PrivateKey()
let harryPublicKeyData = harryPrivateKey.publicKey.rawRepresentation
// Dumbledore and Harry must agree on the salt value
// for creating the symmetric key:
let protocolSalt = "Voldemort's Horcruxes".data(using: .utf8)!
// Dumbledore uses his private key and Harry's public key
// to calculate `sharedSecret` and `symmetricKey`.
let harryPublicKey = try! Curve25519.KeyAgreement.PublicKey(
  rawRepresentation: harryPublicKeyData)
let ADsharedSecret = try! albusPrivateKey.sharedSecretFromKeyAgreement(
  with: harryPublicKey)
let ADsymmetricKey = ADsharedSecret.hkdfDerivedSymmetricKey(
  using: SHA256.self, salt: protocolSalt,
  sharedInfo: Data(), outputByteCount: 32)
// Harry uses his private key and Dumbledore's public key
// to calculate `sharedSecret` and `symmetricKey`.
let albusPublicKey = try! Curve25519.KeyAgreement.PublicKey(
rawRepresentation: albusPublicKeyData)
let HPsharedSecret = try! harryPrivateKey.sharedSecretFromKeyAgreement(
  with: albusPublicKey)
let HPsymmetricKey = HPsharedSecret.hkdfDerivedSymmetricKey(
  using: SHA256.self, salt: protocolSalt,
  sharedInfo: Data(), outputByteCount: 32)
// As if by magic, they produce the same symmetric key!
if ADsymmetricKey == HPsymmetricKey {
  print("Dumbledore and Harry have the same symmetric key.")
}
//: Now Dumbledore and Harry can use symmetric key cryptography to authenticate or encrypt data.
