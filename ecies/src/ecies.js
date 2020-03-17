/**
 * @constant kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
 * @desc Legacy ECIES encryption or decryption,
 *  use kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM in new code.
 *  [x] Encryption is done using AES-GCM with key negotiated by kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256.
 *  [x] AES Key size is 128bit for EC keys <=256bit and 256bit for bigger EC keys.
 *  [x] Ephemeral public key data is used as sharedInfo for KDF.
 *  AES-GCM uses 16 bytes long TAG and all-zero 16 bytes long IV (initialization vector).
 **/

// const crypto = require("crypto");
// crypto.createCipherIv - aes-256-gcm

import { x963kdf } from "./kdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes";
import { concatArrayBuffer, formatToTyped, toBase64 } from "./utils";
import { ec as EC } from "elliptic";

const SupportedECAlogs = ["p256", "secp256k1", "p384", "p521"];

const EC_ALGOS = {
  secp256r1: "p256",
  prime256v1: "p256",
  "P-256": "p256",
  secp256k1: "secp256k1",
  "P-256K": "secp256k1",
  "P-384": "p384",
  secp384r1: "p384",
  "P-521": "p521",
  secp521r1: "p521"
};

const Curves = SupportedECAlogs.reduce((res, c) => {
  res[c] = new EC(c);
  return res;
}, {});

export function generateKeyPair() {
  return P256Curve.genKeyPair();
}

export function computeSecret(privateKey, publicKey) {
  const privateKeyPair = P256Curve.keyFromPrivate(privateKey);
  const publicKeyPair = P256Curve.keyFromPublic(publicKey);
  return privateKeyPair.derive(publicKeyPair.getPublic());
}

class ECIES {
  constructor(ecAlgo, aesKeyBytesLen, aesIvBytesLen) {
    this._ecAlgo = EC_ALGOS[ecAlgo];
    if (!this._ecAlgo) {
      throw new Error("Invalid EC Curve Name: " + ecAlgo);
    }
    this._aesKeyBLen = aesKeyBytesLen;
    this._aesIvBLen = aesIvBytesLen;
    this._keyBLength = this._aesKeyBLen + this._aesIvBLen;

    this._plaintext = null;
    this._sharedSecret = null;
    this._derivedKey = null;
    this._ciphertext = null;

    this.ecdh = null;
    this.kdfHandler = null;
    this.aesHandler = null;
    this.outputHandler = null;
  }

  setInputHandler(inputHandler) {
    this.inputHandler = inputHandler;
    return this;
  }

  setKdf(kdfHandler) {
    this._kdfHandler = kdfHandler;
    return this;
  }

  setAesHandler(aesHandler) {
    this.aesHandler = aesHandler;
    return this;
  }

  setOutputHandler(outputHandler) {
    this.outputHandler = outputHandler;
    return this;
  }

  setPlaintext(plaintext) {
    this._plaintext = plaintext;
    return this;
  }

  setCiphertext(ciphertext) {
    this._ciphertext = ciphertext;
    return this;
  }

  computeSecret(userPubKey, userPrvKey) {
    if (!userPubKey && !userPrvKey) {
      throw new Error(
        "Must Pass User Public Or Private Key To Generate SharedSecret"
      );
    }
    if (userPubKey) {
      this.ecdh = Curves[this.ecAlgo].genKeyPair();
      const publicKeyPair = P256Curve.keyFromPublic(userPubKey);
      this._sharedSecret = this.ecdh.derive(publicKeyPair.getPublic());
      return this;
    }
    this.ecdh = Curves[this.ecAlgo].keyFromPrivate(userPrvKey);
    if (!this.inputHandler) {
      throw new Error("Set Input Handler Before Compute Shared Secret");
    }
    if (!this._ciphertext) {
      throw new Error("Set Cipher Text Before Compute Shared Secret");
    }
    const ephemeralPublicKey = this.inputHandler.getEphemeralPublicKey(
      this._ciphertext
    );
    const ephemeralPublicKeyPair = P256Curve.keyFromPublic(ephemeralPublicKey);
    this._sharedSecret = this.ecdh.derive(ephemeralPublicKeyPair.getPublic());
    return this;
  }

  deriveKey(sharedInfo) {
    if (!this._kdfHandler) {
      throw new Error("Set KDF Handler Before Derive Key");
    }
    this._derivedKey = this._kdfHandler.derive(
      this._sharedSecret,
      this._keyBLength,
      sharedInfo || new Buffer([])
    );
    return this;
  }

  encrypt() {
    if (!this.aesHandler) {
      throw new Error("Set AES Encryption Handler Before Encrypt");
    }
    const symKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const symIv = this._derivedKey.slice(-this._aesIvBLen);
    const message = this.inputHandler.getMessage(this._plaintext);
    this.aesHandler.encrypt(symKey, symIv, message);
    return this;
  }

  decrypt() {
    if (!this.aesHandler) {
      throw new Error("Set Symmertric Encryption Handler Before Decrypt");
    }
    const aesKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const aesIv = this._derivedKey.slice(-this._aesIvBLen);
    const encrypted = this.inputHandler.getEncrypted(this._ciphertext);
    this.aesHandler.decrypt(aesKey, aesIv, encrypted);
    return this;
  }

  output() {
    return this.outputHandler.concat(this);
  }
}

module.exports = {
  ECIES
};

// const KDF_DIGEST_ALGO = "sha256";
// const UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN = 65;
// const AES_KEY_BIT_LEN = 128;
// const AES_KEY_BYTE_LEN = AES_KEY_BIT_LEN / 8;
// const AES_IV_BYTE_LEN = 16;
// const KDF_KEY_LEN = AES_KEY_BYTE_LEN + AES_IV_BYTE_LEN;

// /**
//  * encrypt
//  * @param {Uint8Array} receiverPublicKey
//  * @param {Uint8Array} msg
//  * @returns {Uint8Array}
//  */
// export async function encrypt(receiverPublicKey, msg) {
//   // [x] generate ephemeral key pair and sharedSecret
//   const ephemeralKeyPair = ECDH.generateKeyPair();
//   console.log("receiver public hex: ", toBase64(receiverPublicKey));
//   const sharedSecret = ECDH.computeSecret(
//     ephemeralKeyPair.getPrivate(),
//     receiverPublicKey
//   );
//   // [x] derive aes & mac key using kdf algorithm
//   console.log(ephemeralKeyPair.getPublic());
//   const ephemeralPublicKey = formatToTyped(
//     ephemeralKeyPair.getPublic().encode(),
//     Uint8Array
//   );
//   const derivedKey = x963kdf(
//     sharedSecret.toArrayLike(Uint8Array),
//     KDF_DIGEST_ALGO,
//     KDF_KEY_LEN,
//     ephemeralPublicKey
//   );
//   const aesKey = derivedKey.slice(0, AES_KEY_BYTE_LEN);
//   const aesIV = derivedKey.slice(AES_KEY_BYTE_LEN);
//   const encrypted = await aesGcmEncrypt(aesKey, aesIV, msg);
//   // [x] use aes-128-gcm to encrypt
//   // [x] concat ephemeralPublicKey|encrypted(ciphertext|tag)
//   return concatArrayBuffer([ephemeralPublicKey, encrypted], Uint8Array);
// }

// /**
//  * decrypt
//  * @param {Uint8Array} receiverPrivateKey
//  * @param {Uint8Array} msg
//  * @returns {Uint8Array}
//  */
// export async function decrypt(receiverPrivateKey, msg) {
//   // [x] generate sharedSecret
//   const ephemeralPublicKey = msg.slice(0, UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
//   console.log("decrypt");
//   const sharedSecret = ECDH.computeSecret(
//     receiverPrivateKey,
//     ephemeralPublicKey
//   );
//   // [x] derive aes & mac key using kdf algorithm
//   const derivedKey = x963kdf(
//     sharedSecret.toArrayLike(Uint8Array),
//     KDF_DIGEST_ALGO,
//     KDF_KEY_LEN,
//     ephemeralPublicKey
//   );
//   // [x] use aes-128-gcm to decrypt
//   const encrypted = msg.slice(UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
//   const aesKey = derivedKey.slice(0, AES_KEY_BYTE_LEN);
//   const aesIV = derivedKey.slice(AES_KEY_BYTE_LEN);
//   return aesGcmDecrypt(aesKey, aesIV, encrypted);
// }
