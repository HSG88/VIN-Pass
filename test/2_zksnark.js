/* eslint-disable no-plusplus */
/* eslint-disable no-console */
/* global describe it */
const { expect } = require('chai');
const prover = require('../src/provers/zksnark');
const zkUtils = require('../src/utils/zksnarkUtils');

describe('ZK-SNARKS', () => {
  const messageSize = 6;

  it(`Verifiable Encryption of a message with size = ${messageSize}`, async () => {
    const message = [];
    for (let i = 0; i < messageSize; i++) {
      message.push(BigInt(i + 1)); // message 1, 2, 3 ...
    }
    const commitment = zkUtils.SHA256(message);
    const privateKeyA = zkUtils.genPrivateKey();
    const privateKeyB = zkUtils.genPrivateKey();
    const publicKeyB = zkUtils.genPublicKey(privateKeyB);
    const key = zkUtils.ecdh(privateKeyA, publicKeyB);
    const ciphertext = zkUtils.encrypt(message, key);
    const parameters = {
      publicKey: publicKeyB,
      nonce: ciphertext.nonce,
    };
    const witness = { message, privateKey: privateKeyA };
    console.time('CCE Prove Generation');
    const proof = await prover.prove(parameters, ciphertext.ciphertext,
      commitment, witness, './build/VerifiableEncrypt.wasm', './build/proving.zkey');
    console.timeEnd('CCE Prove Generation');
    const res = await prover.verify(proof, './build/verifying.json');
    expect(res).to.equal(true);
  });
});
