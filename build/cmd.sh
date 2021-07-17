#! /bin/bash
if [ ! -f "potfinal.ptau" ]; then
npx snarkjs powersoftau new bn128 17 pot0.ptau -v
npx snarkjs powersoftau contribute pot0.ptau potfinal.ptau --name="Hisham" -v -e="some random text"
fi
npx circom ../circuits/VerifiableEncrypt.circom --r1cs -v
npx snarkjs zkey new VerifiableEncrypt.r1cs potfinal.ptau tmp0.zkey
npx snarkjs zkey contribute tmp0.zkey proving.zkey --name="Hisham" -v -e="more random text"
npx snarkjs zkey export verificationkey proving.zkey verifying.json
rm tmp*
