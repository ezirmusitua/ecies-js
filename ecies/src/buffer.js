/**
 * concatArrayBuffer
 * @param {[ArrayBuffer|Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array]} input
 * @returns {ArrayBuffer}
 */
function concatArrayBuffer(input, typed = Uint8Array) {
  const outputTotalLen = input.reduce((s, c) => s + c.byteLength, 0);
  const output = new typed(outputTotalLen);
  let targetIdx = 0;
  let targetItemIdx = 0;
  let outputFilledCount = 0;
  while (outputFilledCount < outputTotalLen) {
    let target = input[targetIdx];
    if (ArrayBuffer.isView(target)) {
      target = formatToTyped(target, typed);
    }
    if (target.byteLength > 0) {
      output[outputFilledCount] = target[targetItemIdx];
      outputFilledCount += 1;
      targetItemIdx += 1;
    }
    if (targetItemIdx >= target.byteLength) {
      targetItemIdx = 0;
      targetIdx += 1;
    }
  }
  return output;
}

/**
 * uint8ArrayToHex
 * @param {Uint8Array} array
 * @returns {String}
 */
function uint8ArrayToHex(array) {
  const ui8array = formatToTyped(array, Uint8Array);
  let result = "";
  const ensure8Bits = str =>
    str.length < 2 ? "0".repeat(2 - str.length) + str : str;
  for (let i = 0; i < ui8array.byteLength; i++) {
    result += ensure8Bits(ui8array[i].toString(16));
  }
  return result;
}

/**
 * unicodeToUint8Array
 * @param {String} str
 * @returns {Uint8Array}
 */
function unicodeToUint8Array(str) {
  const escstr = encodeURIComponent(str);
  const binstr = escstr.replace(/%([0-9A-F]{2})/g, (match, p1) => {
    return String.fromCharCode("0x" + p1);
  });
  const ua = new Uint8Array(binstr.length);
  Array.prototype.forEach.call(binstr, function(ch, i) {
    ua[i] = ch.charCodeAt(0);
  });
  return ua;
}

/**
 * uint8ArrayToUnicode
 * @param {ArrayBuffer|Uint16Array} array
 * @returns {String}
 */
function uint8ArrayToUnicode(ua) {
  const binstr = Array.prototype.map
    .call(ua, ch => {
      return String.fromCharCode(ch);
    })
    .join("");
  const escstr = binstr.replace(/(.)/g, function(m, p) {
    let code = p
      .charCodeAt(p)
      .toString(16)
      .toUpperCase();
    if (code.length < 2) {
      code = "0" + code;
    }
    return "%" + code;
  });
  return decodeURIComponent(escstr);
}

/**
 * formatToTyped
 * @param {Array|ArrayBuffer|Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array} input
 * @param {Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array} typed
 * @returns {Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array}
 */
function formatToTyped(input, typed) {
  const isArrayBuffer = input instanceof ArrayBuffer;
  const isTyped = ArrayBuffer.isView(input);
  const isArray = Array.isArray(input);
  if (!isArrayBuffer && !isTyped && !isArray) throw new Error("Invalid type");
  return new typed(isArray ? input : input.buffer);
}

/**
 * fromBase64
 * @param {String} input
 * @returns {ArrayBuffer}
 */
function fromBase64(input) {
  const asciiStr = atob(input);
  const uint8Array = asciiToUint8Array(asciiStr);
  return uint8Array;
}

/**
 * toBase64
 * @param {Uint8Array} input
 * @returns {String}
 */
function toBase64(input) {
  const formattedInput = formatToTyped(input, Uint8Array);
  const asciiStr = uint8ArrayToAscii(formattedInput);
  return btoa(asciiStr);
}

module.exports = {
  concatArrayBuffer,
  uint8ArrayToHex,
  unicodeToUint8Array,
  uint8ArrayToUnicode,
  fromBase64,
  toBase64
};
