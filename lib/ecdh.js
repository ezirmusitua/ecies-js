import { ec as EC } from "elliptic";

const P256Curve = new EC("p256");

export function generateKeyPair() {
    return P256Curve.genKeyPair();
}

export function computeSecret(privateKey, publicKey) {
    const privateKeyPair = P256Curve.keyFromPrivate(privateKey);
    console.log(privateKeyPair.getPublic().encode('hex'));
    const publicKeyPair = P256Curve.keyFromPublic(publicKey);
    console.log(publicKeyPair);
    return privateKeyPair.derive(publicKeyPair.getPublic());
}
