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

import { x963kdf } from "./x963kdf";
import { aesGcmEncrypt, aesGcmDecrypt } from "./aes";
import { concatArrayBuffer, formatToTyped, toBase64 } from "./utils";
import * as ECDH from "./ecdh";

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


const KDF_DIGEST_ALGO = "sha256";
const UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN = 65;
const AES_KEY_BIT_LEN = 128;
const AES_KEY_BYTE_LEN = AES_KEY_BIT_LEN / 8;
const AES_IV_BYTE_LEN = 16;
const KDF_KEY_LEN = AES_KEY_BYTE_LEN + AES_IV_BYTE_LEN;

export const Logger = (() => {
  let _logs = [];
  return {
    log(message) {
      console.log(message);
      _logs.push(message);
    },
    output() {
      return _logs;
    },
    flush() {
      _logs = [];
    }
  };
})();

/**
 * encrypt
 * @param {Uint8Array} receiverPublicKey
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export async function encrypt(receiverPublicKey, msg) {
  // [x] generate ephemeral key pair and sharedSecret
  const ephemeralKeyPair = ECDH.generateKeyPair();
  console.log('receiver public hex: ', toBase64(receiverPublicKey));
  const sharedSecret = ECDH.computeSecret(ephemeralKeyPair.getPrivate(), receiverPublicKey);
  // [x] derive aes & mac key using kdf algorithm
  console.log(ephemeralKeyPair.getPublic());
  const ephemeralPublicKey = formatToTyped(ephemeralKeyPair.getPublic().encode(), Uint8Array);
  const derivedKey = x963kdf(
    sharedSecret.toArrayLike(Uint8Array),
    KDF_DIGEST_ALGO,
    KDF_KEY_LEN,
    ephemeralPublicKey
  );
  const aesKey = derivedKey.slice(0, AES_KEY_BYTE_LEN);
  const aesIV = derivedKey.slice(AES_KEY_BYTE_LEN);
  const encrypted = await aesGcmEncrypt(aesKey, aesIV, msg);
  // [x] use aes-128-gcm to encrypt
  // [x] concat ephemeralPublicKey|encrypted(ciphertext|tag)
  return concatArrayBuffer([ephemeralPublicKey, encrypted], Uint8Array);
}

/**
 * decrypt
 * @param {Uint8Array} receiverPrivateKey
 * @param {Uint8Array} msg
 * @returns {Uint8Array}
 */
export async function decrypt(receiverPrivateKey, msg) {
  // [x] generate sharedSecret
  const ephemeralPublicKey = msg.slice(0, UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
  console.log('decrypt');
  const sharedSecret = ECDH.computeSecret(receiverPrivateKey, ephemeralPublicKey);
  // [x] derive aes & mac key using kdf algorithm
  const derivedKey = x963kdf(
    sharedSecret.toArrayLike(Uint8Array),
    KDF_DIGEST_ALGO,
    KDF_KEY_LEN,
    ephemeralPublicKey
  );
  // [x] use aes-128-gcm to decrypt
  const encrypted = msg.slice(UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
  const aesKey = derivedKey.slice(0, AES_KEY_BYTE_LEN);
  const aesIV = derivedKey.slice(AES_KEY_BYTE_LEN);
  return aesGcmDecrypt(aesKey, aesIV, encrypted);
}
