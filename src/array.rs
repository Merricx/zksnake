use std::str::FromStr;

use num_bigint::BigUint;
use pyo3::prelude::*;
use rayon::prelude::*;

#[pyfunction]
pub fn transpose(mat: Vec<Vec<BigUint>>) -> Vec<Vec<BigUint>> {
    let rows = mat.len();
    let cols = mat[0].len();

    let mut transposed = vec![vec![BigUint::from_str("0").unwrap(); rows]; cols];

    for i in 0..rows {
        for j in 0..cols {
            transposed[j][i] = mat[i][j].clone();
        }
    }

    transposed
}

#[pyfunction]
pub fn dot_product(vec: Vec<BigUint>, mat: Vec<Vec<BigUint>>, modulus: BigUint) -> Vec<BigUint> {
    let num_cols = mat[0].len();
    let mut result: Vec<BigUint> = vec![];

    (0..num_cols).into_iter().for_each(|j| {
        result.push(
            vec.par_iter()
                .enumerate()
                .map(|(i, v)| v * &mat[i][j])
                .sum::<BigUint>()
                % &modulus,
        )
    });

    result
}
