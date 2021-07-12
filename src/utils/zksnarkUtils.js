const {
  babyJub, eddsa, poseidon, poseidonEncrypt, poseidonDecrypt,
} = require('circomlib');

const ethers = require('ethers');
const ff = require('ffjavascript');

/**
 * Converts a bigint to a buffer
 *
 * @param {bigint} bigint - bigint to convert
 * @param {number} [width=32] - width of buffer
 * @returns {Buffer} converted buffer
 */
function bigInt2Buffer(bigint, width = 32) {
  const hex = bigint.toString(16);
  return Buffer.from(hex.padStart(width * 2, '0').slice(0, width * 2), 'hex');
}

/**
 * Converts a buffer to a bigint
 *
 * @param {Buffer} buf - buffer to convert
 * @returns {bigint} converted bigint
 */
function buffer2BigInt(buf) {
  const hex = buf.toString('hex');
  if (hex.length === 0) {
    return BigInt(0);
  }
  return BigInt(`0x${hex}`);
}

/**
 * Derives public key from private key
 *
 * @param {bigint} privKey - private key
 * @returns {Array<bigint>} public key
 */
function genPublicKey(privKey) {
  const pubKey = babyJub.mulPointEscalar(
    babyJub.Base8,
    privKey,
  );

  return pubKey;
}

/**
 * Generate a random BabyJubJub value
 *
 * @returns {bigint} random babyjubjub value
 */
function genRandomBabyJubValue() {
  const sBuff = eddsa.pruneBuffer(
    bigInt2Buffer(
      poseidon([buffer2BigInt(
        Buffer.from(ethers.utils.randomBytes(32)),
      )]),
    ).slice(0, 32),
  );
  const s = ff.utils.leBuff2int(sBuff);
  return ff.Scalar.shr(s, 3);
}

/**
 * Generate a random BabyJubJub key
 *
 * @returns {bigint} random babyjubjub key
 */
function genPrivateKey() {
  return genRandomBabyJubValue();
}

/**
 * Calculate shared key via ECDH
 *
 * @param {bigint} privKey - sender private key
 * @param {Array<bigint>} pubKey - receiver public key
 * @returns {Array<bigInt} shared key
 */
function ecdh(privKey, pubKey) {
  return babyJub.mulPointEscalar(pubKey, privKey);
}

/**
 * SHA256 inputs
 *
 * @param {Array} inputs - inputs to be hashed
 * @returns {bigint} hash value
 */

function SHA256(inputs) {
  return BigInt(ethers.utils.soliditySha256(Array(inputs.length).fill('uint256'), inputs));
}

/*
 * Encrypts a plaintext :BigInt[] using a given key.
 * @return The ciphertext.
 */
function encrypt(plaintext, sharedKey) {
  const nonce = buffer2BigInt(Buffer.from(ethers.utils.randomBytes(16)));
  return { nonce, ciphertext: poseidonEncrypt(plaintext, sharedKey, nonce) };
}

/*
 * Decrypts a ciphertext using a given key.
 * @return The plaintext.
 */
function decrypt(ciphertext, sharedKey) {
  return poseidonDecrypt(ciphertext.ciphertext, sharedKey, ciphertext.nonce,
    ciphertext.ciphertext.length - 1);
}

module.exports = {
  bigInt2Buffer,
  buffer2BigInt,
  genPublicKey,
  genRandomBabyJubValue,
  genPrivateKey,
  ecdh,
  encrypt,
  decrypt,
  SHA256,
};
