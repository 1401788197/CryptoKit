//
//  ViewController.swift
//  test
//
//  Created by Mac027 on 2022/2/22.
//

import CryptoKit
import UIKit
class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // 构造一个salt，生成密钥时需要使用
        let salt = "YungFan".data(using: .utf8)!

        // 用户A和用户B都会生成一对公钥和私钥
        let privateKeyA = P521.KeyAgreement.PrivateKey()
        let publicKeyA = privateKeyA.publicKey

        let privateKeyB = P521.KeyAgreement.PrivateKey()
        let publicKeyB = privateKeyB.publicKey

        // 用户A用私钥和用户B的公钥产生一个共享的密钥
        let sharedSecretA = try? privateKeyA.sharedSecretFromKeyAgreement(with: publicKeyB)
        let symmetricKeyA = sharedSecretA?.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)

        // 用户B用私钥和用户A的公钥产生一个共享的密钥
        let sharedSecretB = try? privateKeyB.sharedSecretFromKeyAgreement(with: publicKeyA)
        let symmetricKeyB = sharedSecretB?.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)

        if symmetricKeyA == symmetricKeyB {
            print("A和B经过协商产生了共享密钥")
        }
        cryptoDemoCombinedData(key: symmetricKeyA!)
    }

    func cryptoDemoCombinedData(key: SymmetricKey) {
        let nonce = try! AES.GCM.Nonce(data: Data(base64Encoded: "fv1nixTVoYpSvpdA")!)
        let tag = Data(base64Encoded: "e1eIgoB4+lA/j3KDHhY4BQ==")!

        // Encrypt
        let sealedBox = try! AES.GCM.seal("123".data(using: .utf8)!, using: key, nonce: nonce, authenticating: tag)

        // Decrypt
        let sealedBoxRestored = try! AES.GCM.SealedBox(combined: sealedBox.combined!)
        let decrypted = try! AES.GCM.open(sealedBoxRestored, using: key, authenticating: tag)

        print("Crypto Demo II\n••••••••••••••••••••••••••••••••••••••••••••••••••\n")
        print("Combined:\n\(sealedBox.combined!.base64EncodedString())\n")
        print("Cipher:\n\(sealedBox.ciphertext.base64EncodedString())\n")
        print("Nonce:\n\(nonce.withUnsafeBytes { Data(Array($0)).base64EncodedString() })\n")
        print("Tag:\n\(tag.base64EncodedString())\n")
        print("Decrypted:\n\(String(data: decrypted, encoding: .utf8)!)\n")
    }
}
