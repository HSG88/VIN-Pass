/* eslint-disable no-plusplus */
/* eslint-disable no-console */
/* global describe it */
const { expect } = require('chai');
const BN = require('bn.js');
const bn128 = require('../src/utils/bn128');
const crypto = require('../src/utils/crypto');
const prover = require('../src/provers/cce');

// rerewee
describe('VIN-Pass CCE', () => {
  const messageSize = 100;
  it(`Verifiable Encryption of a message with size = ${messageSize}`, async () => {
    const parameters = crypto.genParameters();
    const keyPair = crypto.genKeyPair(parameters);
    parameters.alpha2 = keyPair.pubKey;
    const m = new BN('5', 16).toRed(bn128.q);
    const k = bn128.randomScalar();
    const commitment = crypto.commit(parameters, m, k);
    const cipherText = crypto.encrypt(parameters, m, k);
    console.time('CCE Prove Generation');
    const proof = prover.prove(parameters, cipherText, commitment, { m, k });
    for (let i = 1; i < messageSize; i++) {
      prover.prove(parameters, cipherText, commitment, { m, k });
    }
    console.timeEnd('CCE Prove Generation');
    console.time('CCE Verification Time');
    for (let i = 1; i < messageSize; i++) {
      prover.verify(parameters, cipherText, commitment, proof);
    }
    console.timeEnd('CCE Verification Time');
    expect(prover.verify(parameters, cipherText, commitment, proof)).to.equal(true);
  });
});
