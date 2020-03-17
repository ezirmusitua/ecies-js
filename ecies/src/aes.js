import { formatToTyped } from "./utils";
import { AES_GCM } from "asmcrypto.js";

const AES_GCM_TAG_BYTE_LEN = 16;

class GCM {
  constructor(keyBytesLen = 16, tagBytesLen = 16) {
    this.tagBlen = tagBytesLen;
    this.keyBLen = keyBytesLen;
    this.plaintext = null;
    this.ciphertext = null;
    this.tag = null;
    this._completed = false;
  }

  /**
   * aesEncrypt
   * @param {ArrayBuffer|Uint8Array} key
   * @param {ArrayBuffer|Uint8Array} iv
   * @param {ArrayBuffer|Uint8Array|Uint16Array} message
   */
  encrypt(key, iv, message) {
    if (this._completed) return this;
    const formattedKey = formatToTyped(key, Uint8Array);
    const formattedIv = formatToTyped(iv, Uint8Array);
    const formattedMessage = formatToTyped(message, Uint8Array);
    this.ciphertext = AES_GCM.encrypt(
      new Uint8Array(formattedMessage),
      formattedKey,
      formattedIv,
      "",
      this.tagBlen
    );
    this.tag = this.ciphertext.slice(-this.tagBlen);
    return this;
  }

  /**
   * aesDecrypt
   * @param {ArrayBuffer|Uint8Array} key
   * @param {ArrayBuffer|Uint8Array} iv
   * @param {ArrayBuffer|Uint8Array|Uint16Array} ciphertext
   */
  decrypt(key, iv, ciphertext) {
    if (this._completed) return this;
    const formattedKey = formatToTyped(key, Uint8Array);
    const formattedIv = formatToTyped(iv, Uint8Array);
    this.ciphertext = formatToTyped(ciphertext, Uint8Array);
    this.plaintext = AES_GCM.decrypt(
      this.ciphertext,
      formattedKey,
      formattedIv,
      "",
      AES_GCM_TAG_BYTE_LEN
    );
    return this;
  }
}

module.exports = { AES_GCM: GCM };
