const bn128 = require('./bn128');

function genKeyPair(parameters) {
  const prvKey = bn128.randomScalar();
  const pubKey = parameters.alpha1.mul(prvKey);
  return { prvKey, pubKey };
}

function genParameters() {
  return {
    alpha1: bn128.hashToPoint('alpha1'),
    beta1: bn128.hashToPoint('beta1'),
    beta2: bn128.hashToPoint('beta2'),
  };
}

function commit(parameters, m, k) {
  return parameters.beta1.mul(m).add(parameters.beta2.mul(k));
}

function encrypt(parameters, m, k) {
  return {
    c1: parameters.alpha1.mul(k),
    c2: parameters.alpha1.mul(m).add(parameters.alpha2.mul(k)),
  };
}

module.exports = {
  commit, encrypt, genKeyPair, genParameters,
};
