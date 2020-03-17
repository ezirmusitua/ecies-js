const sha256 = require("sha256");
const { concatArrayBuffer, formatToTyped } = require("./utils");

const HASHERS = { sha256: sha256 };

function intTo32BE(i) {
  let iInHexStr = i.toString(16);
  if (iInHexStr.length > 8)
    throw new Error("Integer's bit length is longer than 32");
  iInHexStr = "0".repeat(8 - iInHexStr.length) + iInHexStr;
  const iInHex = iInHexStr.split("").reduce((r, c, i) => {
    if (i % 2 === 0) {
      r.push(c);
    } else {
      r[r.length - 1] += c;
    }
    return r;
  }, []);
  const byteLength = 32 / 8;
  const buf = new Uint8Array(byteLength);
  let pos = byteLength - 1;
  while (pos >= 0) {
    buf[pos] = iInHex[pos];
    pos -= 1;
  }
  return buf;
  // const result = new Uint32Array(1);
  // result[0] = i;
  // return new Uint8Array(result.buffer);
}

class X963KDF {
  constructor(hashAlgo) {
    this.hashAlgo = hashAlgo;
  }

  derive(key, byteLength, sharedInfo) {
    let output = new Uint8Array();
    let outputlen = 0;
    let counter = 1;
    while (byteLength > outputlen) {
      let toHash = concatArrayBuffer([key, intTo32BE(counter)], Uint8Array);
      if (sharedInfo) {
        toHash = concatArrayBuffer([toHash, sharedInfo], Uint8Array);
      }
      const hashResult = formatToTyped(
        HASHERS[this.hashAlgo.toLowerCase()](toHash, { asBytes: true }),
        Uint8Array
      );
      outputlen += hashResult.byteLength;
      output = concatArrayBuffer([output, hashResult], Uint8Array);
      counter += 1;
    }
    return output.slice(0, byteLength);
  }
}

module.exports = { X963KDF };
