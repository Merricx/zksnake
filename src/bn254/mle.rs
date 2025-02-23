use ark_bn254::Fr;
use ark_ff::Zero;
use ark_poly::{MultilinearExtension, SparseMultilinearExtension};

use num_bigint::BigUint;
use pyo3::{prelude::*, types::PyType};

// https://crypto.stackexchange.com/questions/84398/multilinear-extension-polynomial-compute-the-coefficients-of-the-expanded-polyn
fn ext(a: Vec<Fr>) -> Vec<Fr> {
    if a.len() == 1 {
        return vec![a[0]];
    }

    let n = a.len();
    let h = n / 2;
    let (l, r) = a.split_at(h);
    let mut l_result = ext(l.to_vec());
    let r_result = ext(r.to_vec());
    let diff: Vec<Fr> = l_result.iter().zip(r_result).map(|(l, r)| r - l).collect();
    l_result.extend(diff);

    l_result
}

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct MultilinearPolynomial {
    mle: SparseMultilinearExtension<Fr>,
}

#[pymethods]
impl MultilinearPolynomial {
    #[new]
    pub fn new(num_vars: usize, evaluations: Vec<(usize, BigUint)>) -> PyResult<Self> {
        let evals: Vec<(usize, Fr)> = evaluations
            .iter()
            .map(|(i, e)| (*i, Fr::from(e.to_owned())))
            .collect();
        let mle = SparseMultilinearExtension::from_evaluations(num_vars, &evals);
        Ok(MultilinearPolynomial { mle })
    }

    #[getter]
    pub fn num_vars(&self) -> usize {
        self.mle.num_vars
    }

    pub fn evaluate(&self, points: Vec<BigUint>) -> PyResult<BigUint> {
        let points: Vec<Fr> = points.into_iter().map(Into::into).collect();
        SparseMultilinearExtension::evaluate(&self.mle, &points)
            .map(Into::into)
            .ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "Evaluation requires points to be in the same size as the number of variables",
                )
            })
    }

    pub fn permute_evaluations(&self, permutation: Vec<usize>) -> PyResult<Self> {
        let num_vars = self.mle.num_vars;
        assert!(permutation.len() == num_vars);

        let mut permuted_evals = Vec::new();

        // Iterate over the sparse evaluation points
        for (index, &value) in &self.mle.evaluations {
            // Extract binary representation of the index (as a vector of bits)
            let mut bits = vec![0; num_vars];
            for i in 0..num_vars {
                bits[i] = (index >> i) & 1; // Get bit at position i
            }

            // Compute new index based on permutation
            let mut new_index = 0;
            for (i, &p) in permutation.iter().enumerate() {
                new_index |= bits[p] << i; // Place bit in the new position
            }

            // Insert into permuted evaluation map
            permuted_evals.push((new_index, value.into()));
        }

        MultilinearPolynomial::new(num_vars, permuted_evals)
    }

    pub fn partial_evaluate(&self, partial_points: Vec<BigUint>) -> PyResult<Self> {
        let partial_points: Vec<Fr> = partial_points.into_iter().map(Into::into).collect();

        let result = SparseMultilinearExtension::fix_variables(&self.mle, &partial_points);
        Ok(MultilinearPolynomial { mle: result })
    }

    pub fn to_evaluations(&self) -> Vec<BigUint> {
        let evals = SparseMultilinearExtension::to_evaluations(&self.mle);
        evals.into_iter().map(Into::into).collect()
    }

    pub fn to_coefficients(&self) -> Vec<BigUint> {
        let evals = SparseMultilinearExtension::to_evaluations(&self.mle);
        ext(evals).into_iter().map(Into::into).collect()
    }

    pub fn swap(&self, a: usize, b: usize, k: usize) -> PyResult<Self> {
        Ok(MultilinearPolynomial {
            mle: SparseMultilinearExtension::relabel(&self.mle, a, b, k),
        })
    }

    pub fn __str__(&self) -> String {
        format!(
            "SparseMLPolynomial(num_vars={:?}, evaluations={:?})",
            &self.mle.num_vars,
            &self.to_evaluations()
        )
    }

    pub fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn __add__(&self, other: Self) -> PyResult<Self> {
        Ok(MultilinearPolynomial {
            mle: &self.mle + &other.mle,
        })
    }

    pub fn __radd_(&self, other: Self) -> PyResult<Self> {
        self.__add__(other)
    }

    pub fn __sub__(&self, other: Self) -> PyResult<Self> {
        Ok(MultilinearPolynomial {
            mle: &self.mle - &other.mle,
        })
    }

    #[classmethod]
    fn zero<'py>(_cls: &Bound<'py, PyType>) -> PyResult<Self> {
        Ok(MultilinearPolynomial {
            mle: SparseMultilinearExtension::zero(),
        })
    }
}
