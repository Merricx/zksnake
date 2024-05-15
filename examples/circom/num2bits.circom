pragma circom 2.1.0;

include "https://github.com/iden3/circomlib/blob/master/circuits/bitify.circom";

component main{public [in]} = Num2Bits(256);