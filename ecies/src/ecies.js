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

const { ec } = require("elliptic");
const { toBase64 } = require("./buffer");
const EC = ec;

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

class ECIES {
  constructor(ecAlgo, aesKeyBytesLen, aesIvBytesLen) {
    this._ecAlgo = ecAlgo;
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
    let curve;
    if (userPubKey) {
      const curve = Curves[this._ecAlgo];
      this.ecdh = curve.genKeyPair();
      const publicKeyPair = Curves[this._ecAlgo].keyFromPublic(userPubKey);
      this._sharedSecret = this.ecdh
        .derive(publicKeyPair.getPublic())
        .toArrayLike(Uint8Array);
      return this;
    }
    curve = Curves[this._ecAlgo];
    this.ecdh = curve.keyFromPrivate(userPrvKey);
    if (!this.inputHandler) {
      throw new Error("Set Input Handler Before Compute Shared Secret");
    }
    if (!this._ciphertext) {
      throw new Error("Set Cipher Text Before Compute Shared Secret");
    }
    const ephemeralPublicKey = this.inputHandler.getEphemeralPublicKey(
      this._ciphertext
    );
    const ephemeralPublicKeyPair = curve.keyFromPublic(ephemeralPublicKey);
    this._sharedSecret = this.ecdh
      .derive(ephemeralPublicKeyPair.getPublic())
      .toArrayLike(Uint8Array);
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
    const aesKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const aesIv = this._derivedKey.slice(-this._aesIvBLen);
    const message = this.inputHandler.getMessage(this._plaintext);
    this.aesHandler.encrypt(aesKey, aesIv, message);
    return this;
  }

  decrypt() {
    if (!this.aesHandler) {
      throw new Error("Set AES Encryption Handler Before Decrypt");
    }
    const aesKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const aesIv = this._derivedKey.slice(-this._aesIvBLen);
    const encrypted = this.inputHandler.getEncrypted(this._ciphertext);
    this.aesHandler.decrypt(aesKey, aesIv, encrypted);
    return this;
  }

  outputEnc() {
    return this.outputHandler.buildEnc(this);
  }
  outputDec() {
    return this.outputHandler.buildDec(this);
  }
}

module.exports = {
  ECIES,
  EC_ALGOS
};
