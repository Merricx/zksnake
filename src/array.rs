use num_bigint::BigUint;
use pyo3::prelude::*;
use rayon::prelude::*;

type Triplet = (usize, usize, BigUint);

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct SparseArray {
    #[pyo3(get, set)]
    triplets: Vec<Triplet>,
    #[pyo3(get, set)]
    modulus: BigUint,
    #[pyo3(get, set)]
    n_row: usize,
    #[pyo3(get, set)]
    n_col: usize,
}
#[pymethods]
impl SparseArray {
    #[new]
    pub fn new(
        matrix: Vec<Vec<BigUint>>,
        n_row: usize,
        n_col: usize,
        p: BigUint,
    ) -> PyResult<Self> {
        let triplets: Vec<(usize, usize, BigUint)> = matrix
            .par_iter()
            .enumerate()
            .flat_map(|(i, row)| {
                row.par_iter()
                    .enumerate()
                    .filter_map(move |(j, &ref value)| {
                        if *value != BigUint::ZERO {
                            Some((i, j, value.clone()))
                        } else {
                            None
                        }
                    })
            })
            .collect();

        Ok(SparseArray {
            triplets,
            modulus: p,
            n_row,
            n_col,
        })
    }

    pub fn dot(&self, vector: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
        let mut result = vec![BigUint::ZERO; self.n_row];

        for (row, col, value) in &self.triplets {
            result[*row] += vector[*col].clone() * value
        }

        Ok(result)
    }
}
