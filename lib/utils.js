/**
 * concatArrayBuffer
 * @param {[ArrayBuffer|Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array]} input
 * @returns {ArrayBuffer}
 */
export function concatArrayBuffer(input, typed = Uint8Array) {
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
 * asciiToUint8Array
 * @param {String} str
 * @returns {Uint8Array}
 */
export function asciiToUint8Array(str) {
  const chars = [];
  for (let i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
}

/**
 * uint8ArrayToAscii
 * @param {Uint8Array} array
 * @returns {String}
 */
export function uint8ArrayToAscii(array) {
  const ui8array = formatToTyped(array, Uint8Array);
  let result = "";
  for (let i = 0; i < ui8array.byteLength; i++) {
    result += String.fromCharCode(ui8array[i]);
  }
  return result;
}

/**
 * uint8ArrayToHex
 * @param {Uint8Array} array
 * @returns {String}
 */
export function uint8ArrayToHex(array) {
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
export function unicodeToUint8Array(str) {
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
export function uint8ArrayToUnicode(ua) {
  const binstr = Array.prototype.map
    .call(ua, (ch) => {
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
 * @param {ArrayBuffer|Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array} input
 * @param {Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array} typed
 * @returns {Int8Array|Int16Array|Int32Array|Uint8Array|Uint16Array|Uint32Array}
 */
export function formatToTyped(input, typed) {
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
export function fromBase64(input) {
  const asciiStr = atob(input);
  const uint8Array = asciiToUint8Array(asciiStr);
  return uint8Array;
}

// Reference: https://gist.github.com/enepomnyaschih/72c423f727d395eeaa09697058238727

const Base64Charset = (() => {
  let abc = [];
  const A = "A".charCodeAt(0);
  const a = "a".charCodeAt(0);
  const n = "0".charCodeAt(0);
  for (let i = 0; i < 26; ++i) {
    abc.push(String.fromCharCode(A + i));
  }
  for (let i = 0; i < 26; ++i) {
    abc.push(String.fromCharCode(a + i));
  }
  for (let i = 0; i < 10; ++i) {
    abc.push(String.fromCharCode(n + i));
  }
  abc.push("+");
  abc.push("/");
  return abc;
})();

/**
 * uint8ArrayToBase64
 * @param {Uint8Array} bytes
 * @returns {String}
 */
function uint8ArrayToBase64(bytes) {
  let i;
  let result = "";
  let l = bytes.length;
  for (i = 2; i < l; i += 3) {
    result += Base64Charset[bytes[i - 2] >> 2];
    result += Base64Charset[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
    result += Base64Charset[((bytes[i - 1] & 0x0f) << 2) | (bytes[i] >> 6)];
    result += Base64Charset[bytes[i] & 0x3f];
  }
  if (i === l + 1) {
    // 1 octet missing
    result += Base64Charset[bytes[i - 2] >> 2];
    result += Base64Charset[(bytes[i - 2] & 0x03) << 4];
    result += "==";
  }
  if (i === l) {
    // 2 octets missing
    result += Base64Charset[bytes[i - 2] >> 2];
    result += Base64Charset[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
    result += Base64Charset[(bytes[i - 1] & 0x0f) << 2];
    result += "=";
  }
  return result;
}

export function toBase64N(str) {
  const utf8encoder = new TextEncoder();
  return uint8ArrayToBase64(utf8encoder.encode(str));
}

/**
 * toBase64
 * @param {Uint8Array} input
 * @returns {String}
 */
export function toBase64(input) {
  const formattedInput = formatToTyped(input, Uint8Array);
  const asciiStr = uint8ArrayToAscii(formattedInput);
  return btoa(asciiStr);
}
