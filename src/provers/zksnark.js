const snarkjs = require('snarkjs');
const { stringifyBigInts } = require('ffjavascript').utils;
const fs = require('fs');

async function prove(parameters, ciphertext, commitment, witness, wasmPath, zkeyPath) {
  const circuitInput = {
    message: witness.message,
    privateKey: witness.privateKey,
    publicKey: parameters.publicKey,
    ciphertext,
    nonce: parameters.nonce,
    hash: commitment,
  };
  fs.writeFileSync('./build/input.json', JSON.stringify(stringifyBigInts(circuitInput)));
  const proof = await snarkjs.groth16.fullProve(
    circuitInput, wasmPath, zkeyPath,
  );
  return proof;
}

async function verify(proof, vkeyPath) {
  const vkey = JSON.parse(fs.readFileSync(vkeyPath));
  const res = await snarkjs.groth16.verify(vkey, proof.publicSignals, proof.proof);
  return res;
}

module.exports = { prove, verify };
