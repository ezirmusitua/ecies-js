import { formatToTyped } from "./utils";
import { AES_GCM } from "asmcrypto.js";
// import { Logger } from "./ecies";

const AES_GCM_TAG_BYTE_LEN = 16;

/**
 * aesEncrypt
 * @param {ArrayBuffer|Uint8Array} key
 * @param {ArrayBuffer|Uint8Array} iv
 * @param {ArrayBuffer|Uint8Array|Uint16Array} message
 */
export async function aesGcmEncrypt(key, iv, message) {
  const formattedKey = formatToTyped(key, Uint8Array);
  // Logger.log(formattedKey);
  const formattedIv = formatToTyped(iv, Uint8Array);
  // Logger.log(formattedIv);
  const formattedMessage = formatToTyped(message, Uint8Array);
  // Logger.log(formattedMessage);
  const output = AES_GCM.encrypt(
    new Uint8Array(formattedMessage),
    formattedKey,
    formattedIv,
    "",
    AES_GCM_TAG_BYTE_LEN
  );
  // encrypted = encrypted + tag
  // console.log('message: ', formattedMessage);
  // console.log('key: ', formattedKey);
  // console.log('IV: ', formattedIv);
  // console.log('encrypted: ', output);
  return output;
}

/**
 * aesDecrypt
 * @param {ArrayBuffer|Uint8Array} key
 * @param {ArrayBuffer|Uint8Array} iv
 * @param {ArrayBuffer|Uint8Array|Uint16Array} cipherText
 */
export function aesGcmDecrypt(key, iv, cipherText) {
  const formattedKey = formatToTyped(key, Uint8Array);
  const formattedIv = formatToTyped(iv, Uint8Array);
  const formattedCipherText = formatToTyped(cipherText, Uint8Array);
  // console.log('input: ', cipherText);
  // console.log('key: ', formattedKey);
  // console.log('IV: ', formattedIv);
  // console.log('cipherText: ', formattedCipherText);
  return AES_GCM.decrypt(
    formattedCipherText,
    formattedKey,
    formattedIv,
    "",
    AES_GCM_TAG_BYTE_LEN
  );
}
