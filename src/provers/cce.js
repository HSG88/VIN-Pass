const { solidityKeccak256 } = require('ethers').utils;
const { BigNumber } = require('ethers');
const BN = require('bn.js');
const bn128 = require('../utils/bn128');

function prove(parameters, cipherText, commitment, witness) {
  const m1 = bn128.randomScalar();
  const k1 = bn128.randomScalar();
  const a1 = parameters.alpha1.mul(k1);
  const a2 = parameters.alpha1.mul(m1).add(parameters.alpha2.mul(k1));
  const a3 = parameters.beta1.mul(m1).add(parameters.beta2.mul(k1));
  const hash = solidityKeccak256(['uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint', 'uint'],
    [BigNumber.from(a1.getX().toArray()), BigNumber.from(a1.getY().toArray()),
      BigNumber.from(a2.getX().toArray()), BigNumber.from(a2.getY().toArray()),
      BigNumber.from(a3.getX().toArray()), BigNumber.from(a3.getY().toArray()),
      BigNumber.from(cipherText.c2.getX().toArray()),
      BigNumber.from(cipherText.c2.getY().toArray()),
      BigNumber.from(commitment.getX().toArray()),
      BigNumber.from(commitment.getY().toArray()),
      BigNumber.from(cipherText.c1.getX().toArray()),
      BigNumber.from(cipherText.c1.getY().toArray()),
    ]);
  const c = new BN(hash.slice(2), 16).toRed(bn128.q);
  const t = m1.redSub(witness.m.redMul(c));
  const u = k1.redSub(witness.k.redMul(c));
  return {
    a1,
    a2,
    a3,
    t,
    u,
    c,
  };
}

function verify(parameters, ciphertext, commitment, proof) {
  const aa1 = parameters.alpha1.mul(proof.u).add(ciphertext.c1.mul(proof.c));
  const aa2 = parameters.alpha1.mul(proof.t).add(parameters.alpha2.mul(proof.u))
    .add(ciphertext.c2.mul(proof.c));
  const aa3 = parameters.beta1.mul(proof.t).add(parameters.beta2.mul(proof.u))
    .add(commitment.mul(proof.c));
  return bn128.eq(proof.a1, aa1) && bn128.eq(proof.a2, aa2)
  && bn128.eq(proof.a3, aa3);
}

module.exports = { prove, verify };
