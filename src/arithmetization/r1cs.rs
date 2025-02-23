use std::collections::HashMap;

use ark_ff::One;
use num_bigint::BigUint;
use rayon::prelude::*;
use super::symbolic::{ ConstraintSystem, Equation, Node };

fn transform(
    row: usize,
    eq: &Node,
    witness_map: &Vec<String>,
    v: &mut Vec<(usize, usize, BigUint)>,
    modulus: &BigUint,
    is_neg: bool
) {
    match &eq.gate {
        super::symbolic::Gate::Const(c) => {
            if is_neg {
                v.push((row, 0, modulus - c.to_owned()));
            } else {
                v.push((row, 0, c.to_owned()));
            }
        }
        super::symbolic::Gate::Input(name) => {
            let index = witness_map
                .iter()
                .position(|x| x == name)
                .unwrap();
            if is_neg {
                v.push((row, index, modulus - BigUint::one()));
            } else {
                v.push((row, index, BigUint::one()));
            }
        }
        super::symbolic::Gate::Add(left, right) => {
            transform(row, left, witness_map, v, modulus, is_neg);
            transform(row, right, witness_map, v, modulus, is_neg);
        }
        super::symbolic::Gate::Sub(left, right) => {
            transform(row, left, witness_map, v, modulus, is_neg);
            transform(row, right, witness_map, v, modulus, true);
        }
        super::symbolic::Gate::Mul(left, right) => {
            match (&left.gate, &right.gate) {
                (super::symbolic::Gate::Input(name), super::symbolic::Gate::Const(value)) => {
                    let index = witness_map
                        .iter()
                        .position(|x| x == name)
                        .unwrap();
                    if is_neg {
                        v.push((row, index, modulus - value));
                    } else {
                        v.push((row, index, value.to_owned()));
                    }
                }
                (super::symbolic::Gate::Const(value), super::symbolic::Gate::Input(name)) => {
                    let index = witness_map
                        .iter()
                        .position(|x| x == name)
                        .unwrap();
                    if is_neg {
                        v.push((row, index, modulus - value));
                    } else {
                        v.push((row, index, value.to_owned()));
                    }
                }
                _ => {
                    panic!("Invalid R1CS: {}", eq.to_expression());
                }
            }
        }
        super::symbolic::Gate::Div(_, _) => panic!("Invalid R1CS: {}", eq.to_expression()),
        super::symbolic::Gate::Neg(left) => {
            transform(row, left, witness_map, v, modulus, true);
        }
    }
}

fn consume_constraint(
    row: usize,
    constraint: &Equation,
    witness_map: &Vec<String>,
    modulus: &BigUint
) -> (Vec<(usize, usize, BigUint)>, Vec<(usize, usize, BigUint)>, Vec<(usize, usize, BigUint)>) {
    let mut a: Vec<(usize, usize, BigUint)> = vec![];
    let mut b: Vec<(usize, usize, BigUint)> = vec![];
    let mut c: Vec<(usize, usize, BigUint)> = vec![];

    let lhs = constraint.lhs.clone();
    let rhs = constraint.rhs.clone();

    match &rhs.gate {
        super::symbolic::Gate::Const(_) => {
            transform(row, &rhs, witness_map, &mut a, modulus, false);
            b.push((row, 0, BigUint::one()));
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
        super::symbolic::Gate::Input(_) => {
            transform(row, &rhs, witness_map, &mut a, modulus, false);
            b.push((row, 0, BigUint::one()));
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
        super::symbolic::Gate::Add(_, _) => {
            transform(row, &rhs, witness_map, &mut a, modulus, false);
            b.push((row, 0, BigUint::one()));
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
        super::symbolic::Gate::Sub(_, _) => {
            transform(row, &rhs, witness_map, &mut a, modulus, true);
            b.push((row, 0, BigUint::one()));
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
        super::symbolic::Gate::Mul(rhs_left, rhs_right) => {
            transform(row, rhs_left, witness_map, &mut a, modulus, false);
            transform(row, rhs_right, witness_map, &mut b, modulus, false);
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
        super::symbolic::Gate::Div(rhs_left, rhs_right) => {
            transform(row, rhs_left, witness_map, &mut c, modulus, false);
            transform(row, rhs_right, witness_map, &mut b, modulus, false);
            transform(row, &lhs, witness_map, &mut a, modulus, false);
        }
        super::symbolic::Gate::Neg(_) => {
            transform(row, &rhs, witness_map, &mut a, modulus, true);
            b.push((row, 0, BigUint::one()));
            transform(row, &lhs, witness_map, &mut c, modulus, false);
        }
    }

    (a, b, c)
}

pub fn get_witness_vector(
    vars: &HashMap<String, BigUint>,
    inputs: &Vec<String>,
    outputs: &Vec<String>,
    public_vars: &Vec<String>
) -> Vec<String> {
    let mut public_input: Vec<String> = vec![];
    let mut private_input: Vec<String> = vec![];
    let mut intermediate_vars: Vec<String> = vec![];

    vars.keys()
        .into_iter()
        .for_each(|v| (
            if public_vars.contains(v) && inputs.contains(v) {
                public_input.push(v.to_string());
            } else if inputs.contains(v) && !public_vars.contains(v) {
                private_input.push(v.to_string());
            } else if !outputs.contains(v) {
                intermediate_vars.push(v.to_string());
            }
        ));

    let witness: Vec<String> = [
        vec!["0".to_string()],
        outputs.to_vec(),
        public_input,
        private_input,
        intermediate_vars,
    ]
        .into_iter()
        .flatten()
        .collect();

    witness
}

pub fn compile(
    cs: &ConstraintSystem
) -> Vec<
    (Vec<(usize, usize, BigUint)>, Vec<(usize, usize, BigUint)>, Vec<(usize, usize, BigUint)>)
> {
    let witness_map = get_witness_vector(&cs.vars, &cs.inputs, &cs.outputs, &cs.public_vars);

    let result: Vec<_> = cs.constraints
        .clone()
        .into_par_iter()
        .enumerate()
        .map(|(row, constraint)| {
            consume_constraint(row, &constraint, &witness_map, &cs.modulus)
        })
        .collect();

    result
}
