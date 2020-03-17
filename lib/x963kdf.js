import sha256 from "sha256";
import { concatArrayBuffer, formatToTyped } from "./utils";
import {Logger} from './ecies';
import {toBase64} from './utils';

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

export function x963kdf(key, algo, byteLength, sharedInfo) {
  let output = new Uint8Array();
  let outputlen = 0;
  let counter = 1;
  Logger.log("X963KDF: \n\t" + toBase64(key) + "\n\t" + algo + "\n\t" + byteLength + "\n\t" + toBase64(sharedInfo));
  while (byteLength > outputlen) {
    Logger.log("int to 32 BigE: " + intTo32BE(counter))
    let toHash = concatArrayBuffer([key, intTo32BE(counter)], Uint8Array);
    if (sharedInfo) {
      toHash = concatArrayBuffer([toHash, sharedInfo], Uint8Array);
    }
    console.log(HASHERS[algo.toLowerCase()](toHash, {asBytes: true}));
    const hashResult = formatToTyped(HASHERS[algo.toLowerCase()](toHash, {asBytes: true}), Uint8Array);
    outputlen += hashResult.byteLength;
    console.log(output);
    output = concatArrayBuffer([output, hashResult], Uint8Array);
    counter += 1;
  }
  console.log("Raw: ", output);
  Logger.log('X963KDF Result: ' + toBase64(output.slice(0, byteLength)));
  return output.slice(0, byteLength);
}
