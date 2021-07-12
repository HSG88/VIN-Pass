/* eslint-disable no-constant-condition */
/* eslint-disable new-cap */
const BN = require('bn.js');
const EC = require('elliptic');
const crypto = require('crypto');
const { keccak256, toUtf8Bytes } = require('ethers').utils;

// y^2 = x3 + 3 /  EIP-197
const FIELD_MODULUS = new BN('30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47', 16);
const GROUP_MODULUS = new BN('30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001', 16);
const bn128 = {};

bn128.curve = new EC.curve.short({
  a: '0',
  b: '3',
  p: FIELD_MODULUS,
  n: GROUP_MODULUS,
  gRed: false,
  g: ['077da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4', '01485efa927f2ad41bff567eec88f32fb0a0f706588b4e41a8d587d008b7f875'],
});
bn128.hashToPoint = (input) => {
  // seed is flattened 0x + hex string
  const seed = keccak256(toUtf8Bytes(input));
  const seedRed = new BN(seed.slice(2), 16).toRed(bn128.p);
  const p14 = bn128.curve.p.add(new BN(1)).div(new BN(4));
  while (true) {
    const ySquared = seedRed
      .redPow(new BN(3))
      .redAdd(new BN(3).toRed(bn128.p));
    const y = ySquared.redPow(p14);
    if (y.redPow(new BN(2)).eq(ySquared)) {
      return bn128.curve.point(seedRed.fromRed(), y.fromRed());
    }
    seedRed.redIAdd(new BN(1).toRed(bn128.p));
  }
};

bn128.zero = bn128.curve.g.mul(0);

bn128.p = BN.red(bn128.curve.p);
bn128.q = BN.red(bn128.curve.n);

bn128.randomScalar = () => new BN(crypto.randomBytes(32), 16).toRed(bn128.q);
bn128.eq = (a, b) => a.getX().toString() === b.getX().toString()
&& a.getY().toString() === b.getY().toString();

module.exports = bn128;
