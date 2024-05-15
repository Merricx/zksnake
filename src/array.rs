use num_bigint::BigUint;
use pyo3::prelude::*;
use rayon::prelude::*;

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
