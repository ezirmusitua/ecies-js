const { ECIES, EC_ALGOS } = require("./ecies");
const { X963KDF } = require("./kdf");
const { AES_GCM } = require("./aes");
const {
  concatArrayBuffer,
  fromBase64,
  unicodeToUint8Array,
  uint8ArrayToUnicode,
  toBase64,
  formatToTyped
} = require("./buffer");

const AES_GCM_IV_BYTES_LEN = 16;
const KDF_HASH_ALGO = "sha256";

class InputHandler {
  constructor(pubBytesLen) {
    this.pubBytesLen = pubBytesLen;
  }
  formatInput(i, enc = "utf8") {
    if (i instanceof ArrayBuffer || ArrayBuffer.isView(i))
      return formatToTyped(i, Uint8Array);
    if (enc === "base64") return fromBase64(i);
    return unicodeToUint8Array(i);
  }
  getMessage(i) {
    return this.formatInput(i);
  }
  getEphemeralPublicKey(i) {
    return this.formatInput(i, "base64").slice(0, this.pubBytesLen);
  }
  getEncrypted(i) {
    return this.formatInput(i, "base64").slice(this.pubBytesLen);
  }
}

class OutputHandler {
  constructor() {}
  buildDec(eciesInstance) {
    return uint8ArrayToUnicode(eciesInstance.aesHandler.plaintext);
  }
  buildEnc(eciesInstance) {
    const publicCodePoint = formatToTyped(
      eciesInstance.ecdh.getPublic().encode(),
      Uint8Array
    );
    const encrypted = eciesInstance.aesHandler.ciphertext;
    const tag = eciesInstance.aesHandler.tag;
    return toBase64(
      concatArrayBuffer([publicCodePoint, encrypted, tag], Uint8Array)
    );
  }
}

function createECIESInstance(ecAlgo, aesKeyBytesLen, pubBytesLen) {
  const kdfHandler = new X963KDF(KDF_HASH_ALGO);
  const aesHandler = new AES_GCM(aesKeyBytesLen, AES_GCM_IV_BYTES_LEN);
  const ecies = new ECIES(ecAlgo, aesKeyBytesLen, AES_GCM_IV_BYTES_LEN);
  return ecies
    .setInputHandler(new InputHandler(pubBytesLen))
    .setKdf(kdfHandler)
    .setAesHandler(aesHandler)
    .setOutputHandler(new OutputHandler());
}

function kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(ecAlgo) {
  let pubBytesLen = 65;
  let aesKeyBytesLen = 16;
  const formattedEcAlgo = EC_ALGOS[ecAlgo];
  if (["p256k1", "p256"].indexOf(formattedEcAlgo) === -1) {
    aesKeyBytesLen = 32;
    // TODO: Update public key bytes length
    // pubBytesLen = ??;
  }
  
  return {
    encrypt(pubKey, message) {
      const ecies = createECIESInstance(
        formattedEcAlgo,
        aesKeyBytesLen,
        pubBytesLen
      );
      return ecies
        .setPlaintext(message)
        .computeSecret(pubKey)
        .deriveKey(formatToTyped(ecies.ecdh.getPublic().encode(), Uint8Array))
        // .deriveKey("")
        .encrypt()
        .outputEnc();
    },
    decrypt(prvKey, ciphertext) {
      const ecies = createECIESInstance(
        formattedEcAlgo,
        aesKeyBytesLen,
        pubBytesLen
      );
      return ecies
        .setCiphertext(ciphertext)
        .computeSecret(null, prvKey)
        .deriveKey(ecies.inputHandler.getEphemeralPublicKey(ecies._ciphertext))
        // .deriveKey("")
        .decrypt()
        .outputDec();
    }
  };
}

module.exports = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
