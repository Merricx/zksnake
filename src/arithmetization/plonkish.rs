use ark_ff::{ One, Zero };
use num_bigint::BigUint;
use rayon::prelude::*;
use super::circuit::{ ConstraintSystem, Equation, Node };

fn transform(
    eq: &Node,
    q_var: &mut BigUint,
    q_constant: &mut BigUint,
    var_mul: &mut usize,
    touched_var: &mut Vec<String>,
    modulus: &BigUint
) {
    match &eq.gate {
        super::circuit::Gate::Input(name) => {
            *var_mul += 1;
            touched_var.push(name.to_string());
        }
        super::circuit::Gate::Add(left, right) => {
            transform(left, q_var, q_constant, var_mul, touched_var, modulus);
            transform(right, q_var, q_constant, var_mul, touched_var, modulus);
        }
        super::circuit::Gate::Sub(left, right) => {
            transform(left, q_var, q_constant, var_mul, touched_var, modulus);
            transform(right, q_var, q_constant, var_mul, touched_var, modulus);
        }
        super::circuit::Gate::Mul(left, right) => {
            match (&left.gate, &right.gate) {
                (_, super::circuit::Gate::Const(value)) => {
                    transform(left, q_var, q_constant, var_mul, touched_var, modulus);
                    *q_var *= value;
                }
                (super::circuit::Gate::Const(value), _) => {
                    *q_var *= value;
                    transform(right, q_var, q_constant, var_mul, touched_var, modulus);
                }
                _ => {
                    transform(left, q_var, q_constant, var_mul, touched_var, modulus);
                    transform(right, q_var, q_constant, var_mul, touched_var, modulus);
                }
            }
        }
        super::circuit::Gate::Neg(left) => {
            transform(left, q_var, q_constant, var_mul, touched_var, modulus);
            *q_var = modulus - q_var.clone();
        }
        super::circuit::Gate::Const(val) => {
            *q_constant += val;
        }
        _ => {
            panic!("Invalid plonkish constraint: {}", eq.to_expression());
        }
    }
}

fn copy_constraint(num_constraint: usize, witness: Vec<&String>) -> Vec<usize> {
    let size = witness.len();
    let padded_size = num_constraint.next_power_of_two() * 3;
    let mut padded_witness: Vec<String> = witness
        .iter()
        .map(|s| s.to_string())
        .collect();
    padded_witness.extend(vec![Default::default(); padded_size - size].iter().cloned());

    let mut w: Vec<&String> = Vec::new();
    for i in 0..3 {
        w.extend(padded_witness.iter().skip(i).step_by(3));
    }

    let mut permutation: Vec<usize> = (0..padded_size).collect();

    for i in 0..size {
        if w[i].is_empty() {
            continue;
        }
        for j in i + 1..size {
            if w[i] == w[j] {
                permutation.swap(i, j);
                break;
            }
        }
    }

    permutation
}

fn consume_constraint(
    constraint: &Equation,
    public_input: &Vec<String>,
    modulus: &BigUint
) -> (BigUint, BigUint, BigUint, BigUint, BigUint, [String; 3]) {
    let mut ql = BigUint::zero();
    let mut qr = BigUint::zero();
    let mut qo = BigUint::zero();
    let mut qm = BigUint::zero();
    let mut qc = BigUint::zero();
    let mut w: [String; 3] = Default::default();

    let lhs = constraint.lhs.clone();
    let rhs = constraint.rhs.clone();

    if let super::circuit::Gate::Const(left) = lhs.gate {
        qc = modulus - left;
    } else if let super::circuit::Gate::Input(var) = lhs.gate {
        if !public_input.contains(&var) {
            qo = modulus - BigUint::one();
        }
        w[2] = var.to_string();
    } else {
        panic!("Constraint {} not in the form of C=A*B", constraint.__repr__().unwrap());
    }

    match &rhs.gate {
        super::circuit::Gate::Const(val) => {
            qc += val;
        }
        super::circuit::Gate::Input(name) => {
            ql = BigUint::one();
            w[0] = name.to_string();

            qr = BigUint::zero();
        }
        super::circuit::Gate::Add(left, right) => {
            ql = BigUint::one();
            qr = BigUint::one();

            let mut var_mul: usize = 0;
            let mut touched_var = vec![];
            transform(left, &mut ql, &mut qc, &mut var_mul, &mut touched_var, modulus);
            transform(right, &mut qr, &mut qc, &mut var_mul, &mut touched_var, modulus);

            if var_mul == 0 {
                ql = BigUint::zero();
                qr = BigUint::zero();
            } else if var_mul <= 1 {
                ql %= modulus;
                w[0] = touched_var[0].to_string();

                qr = BigUint::zero();
            } else if var_mul == 2 {
                ql %= modulus;
                qr %= modulus;

                w[0] = touched_var[0].to_string();
                w[1] = touched_var[1].to_string();
            } else {
                panic!(
                    "More than two variables in single gate: {}",
                    constraint.__repr__().unwrap()
                );
            }
        }
        super::circuit::Gate::Sub(left, right) => {
            ql = BigUint::one();
            qr = BigUint::one();

            let mut var_mul: usize = 0;
            let mut touched_var = vec![];
            transform(left, &mut ql, &mut qc, &mut var_mul, &mut touched_var, modulus);
            transform(right, &mut qr, &mut qc, &mut var_mul, &mut touched_var, modulus);

            if var_mul == 0 {
                ql = BigUint::zero();
                qr = BigUint::zero();
            } else if var_mul <= 1 {
                ql %= modulus;
                w[0] = touched_var[0].to_string();

                qr = BigUint::zero();
            } else if var_mul == 2 {
                ql %= modulus;
                if public_input.contains(&touched_var[1]) {
                    qr = BigUint::zero();
                } else {
                    qr = modulus - (qr % modulus);
                }

                w[0] = touched_var[0].to_string();
                w[1] = touched_var[1].to_string();
            } else {
                panic!(
                    "More than two variables in single gate: {}",
                    constraint.__repr__().unwrap()
                );
            }
        }
        super::circuit::Gate::Mul(_, _) => {
            let mut q_var = BigUint::one();
            let mut q_const = BigUint::zero();

            let mut var_mul: usize = 0;
            let mut touched_var = vec![];
            transform(&rhs, &mut q_var, &mut q_const, &mut var_mul, &mut touched_var, modulus);

            if var_mul == 0 {
                qc = q_const;
            } else if var_mul == 1 {
                ql = q_var % modulus;
                w[0] = touched_var[0].to_string();
            } else if var_mul == 2 {
                w[0] = touched_var[0].to_string();
                w[1] = touched_var[1].to_string();

                qm = q_var % modulus;
            } else {
                panic!(
                    "More than two variables in single gate: {}",
                    constraint.__repr__().unwrap()
                );
            }
        }
        super::circuit::Gate::Div(_, _) => {
            panic!("Division operation is not supported");
        }
        super::circuit::Gate::Neg(left) => {
            ql = BigUint::one();
            qr = BigUint::zero();

            let mut var_mul: usize = 0;
            let mut touched_var = vec![];
            transform(left, &mut ql, &mut qc, &mut var_mul, &mut touched_var, modulus);
            if var_mul == 0 {
                ql = BigUint::zero();
            } else {
                if !public_input.contains(&touched_var[0]) {
                    ql = modulus - (ql % modulus);
                } else {
                    ql = BigUint::zero();
                }

                w[0] = touched_var[0].to_string();
            }
        }
    }

    if w[0].is_empty() && !w[1].is_empty() {
        w.swap(1, 0);
    }

    (ql, qr, qo, qm, qc, w)
}

pub fn compile(
    cs: &ConstraintSystem
) -> (Vec<(BigUint, BigUint, BigUint, BigUint, BigUint, [String; 3])>, Vec<usize>) {
    let mut witness = vec![];
    let result: Vec<_> = cs.constraints
        .clone()
        .into_par_iter()
        .enumerate()
        .map(|(_, constraint)| { consume_constraint(&constraint, &cs.public_vars, &cs.modulus) })
        .collect();

    result.iter().for_each(|(_, _, _, _, _, w)| witness.extend(w));

    let permutation = copy_constraint(cs.num_constraints(), witness);

    (result, permutation)
}
