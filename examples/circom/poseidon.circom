pragma circom 2.1.6;

include "circuits/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Example () {
    signal input a;
    signal input b;
    signal input c;
    signal output h;
    
    component hash = Poseidon(3);
    hash.inputs[0] <== a;
    hash.inputs[1] <== b;
    hash.inputs[2] <== c;

    h <== hash.out;
}

component main = Example();