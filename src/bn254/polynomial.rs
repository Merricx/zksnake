use ark_bn254::Fr;
use ark_poly::{
    polynomial::univariate::DensePolynomial,
    univariate,
    DenseUVPolynomial,
    EvaluationDomain,
    GeneralEvaluationDomain,
    Polynomial,
};
use num_bigint::BigUint;
use pyo3::{ exceptions::{ PyRuntimeError, PyValueError }, prelude::* };
use rayon::prelude::*;

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialRing {
    poly: DensePolynomial<Fr>,
    domain: GeneralEvaluationDomain<Fr>,
}

#[pymethods]
impl PolynomialRing {
    #[new]
    pub fn new(coeffs: Vec<BigUint>) -> PyResult<Self> {
        let mut fp_coeffs = vec![];
        for coeff in coeffs.clone() {
            fp_coeffs.push(Fr::from(coeff));
        }
        let poly = DensePolynomial::from_coefficients_vec(fp_coeffs);
        let domain = EvaluationDomain::new(coeffs.len()).unwrap();
        Ok(PolynomialRing { poly, domain })
    }

    pub fn __str__(&self) -> String {
        let degree = self.poly.coeffs.len() - 1;
        let mut str: String = String::new();
        for (i, &coeff) in self.poly.coeffs.iter().rev().enumerate() {
            let exponent = degree - i;

            if coeff != Fr::from(0) {
                if i != 0 {
                    str.push_str(" + ");
                }
                if exponent > 1 {
                    str.push_str(&format!("{}x^{}", coeff, exponent));
                } else if exponent == 1 {
                    str.push_str(&format!("{}x", coeff));
                } else {
                    str.push_str(&format!("{}", coeff));
                }
            }
        }
        str
    }

    pub fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn coeffs(&self) -> PyResult<Vec<BigUint>> {
        let mut r = vec![];
        for c in &self.poly.coeffs {
            r.push(c.to_owned().into());
        }
        Ok(r)
    }

    pub fn degree(&self) -> PyResult<BigUint> {
        Ok((self.poly.coeffs.len() - 1).into())
    }

    pub fn __add__(&self, other: &PyAny) -> PyResult<Self> {
        if let Ok(other_int) = other.extract::<BigUint>() {
            let mut coeffs = self.poly.coeffs.clone();
            let adder: Fr = other_int.into();
            coeffs[0] = coeffs[0] + adder;

            Ok(PolynomialRing {
                poly: DensePolynomial::from_coefficients_vec(coeffs.to_vec()),
                domain: self.domain,
            })
        } else if let Ok(other_poly) = other.extract::<PolynomialRing>() {
            Ok(PolynomialRing {
                poly: self.poly.clone() + other_poly.poly,
                domain: self.domain,
            })
        } else {
            Err(
                pyo3::exceptions::PyTypeError::new_err(
                    format!("Unsupported type for addition: {:?}", other.get_type().name())
                )
            )
        }
    }

    pub fn __neg__(&self) -> PyResult<Self> {
        Ok(PolynomialRing {
            poly: -self.poly.clone(),
            domain: self.domain,
        })
    }

    pub fn __sub__(&self, other: &PyAny) -> PyResult<Self> {
        if let Ok(other_int) = other.extract::<BigUint>() {
            let mut coeffs = self.poly.coeffs.clone();
            let subtractor: Fr = other_int.into();
            coeffs[0] = coeffs[0] - subtractor;

            Ok(PolynomialRing {
                poly: DensePolynomial::from_coefficients_vec(coeffs.to_vec()),
                domain: self.domain,
            })
        } else if let Ok(other_poly) = other.extract::<PolynomialRing>() {
            Ok(PolynomialRing {
                poly: self.poly.clone() + -other_poly.poly,
                domain: self.domain,
            })
        } else {
            Err(
                pyo3::exceptions::PyTypeError::new_err(
                    format!("Unsupported type for addition: {:?}", other.get_type().name())
                )
            )
        }
    }

    pub fn __mul__(&self, other: Self) -> PyResult<Self> {
        Ok(PolynomialRing {
            poly: DensePolynomial::naive_mul(&self.poly, &other.poly),
            domain: self.domain,
        })
    }

    pub fn __truediv__(&self, other: Self) -> PyResult<[PolynomialRing; 2]> {
        let result = univariate::DenseOrSparsePolynomial::divide_with_q_and_r(
            &self.poly.clone().into(),
            &other.poly.into()
        );

        match result {
            Some((quotient, remainder)) => {
                let q_coeffs = quotient.coeffs.len();
                let r_coeffs = remainder.coeffs.len();
                Ok(
                    (
                        PolynomialRing {
                            poly: quotient,
                            domain: EvaluationDomain::new(q_coeffs).unwrap(),
                        },
                        PolynomialRing {
                            poly: remainder,
                            domain: EvaluationDomain::new(r_coeffs).unwrap(),
                        },
                    ).into()
                )
            }
            None => Err(PyRuntimeError::new_err("Polynomial division error")),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.poly.coeffs.len() == 0
    }

    pub fn divide_by_vanishing_poly(&self) -> PyResult<[PolynomialRing; 2]> {
        let result = DensePolynomial::divide_by_vanishing_poly(&self.poly, self.domain);
        match result {
            Some((quotient, remainder)) =>
                Ok(
                    (
                        PolynomialRing {
                            poly: quotient,
                            domain: self.domain,
                        },
                        PolynomialRing {
                            poly: remainder,
                            domain: self.domain,
                        },
                    ).into()
                ),
            None => Err(PyRuntimeError::new_err("Cannot divided by vanishing poly")),
        }
    }

    pub fn __call__(&self, point: BigUint) -> PyResult<BigUint> {
        let eval = DensePolynomial::evaluate(&self.poly, &Fr::from(point));
        Ok(eval.into())
    }
}

#[pyfunction]
pub fn fft(coeffs: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
    let mut domain_coeff = vec![];
    for c in &coeffs {
        domain_coeff.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(coeffs.len()).unwrap();
    let evals = EvaluationDomain::fft(&domain, &domain_coeff);

    Ok(
        evals
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn coset_fft(coeffs: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
    let mut domain_coeff = vec![];
    for c in &coeffs {
        domain_coeff.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(coeffs.len()).unwrap();
    let generator = EvaluationDomain::group_gen(&domain);
    let coset_domain = EvaluationDomain::get_coset(&domain, generator).unwrap();
    let evals = EvaluationDomain::fft(&coset_domain, &domain_coeff);

    Ok(
        evals
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn ifft(evals: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
    let mut domain_evals = vec![];
    for c in &evals {
        domain_evals.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(evals.len()).unwrap();
    let coeffs = EvaluationDomain::ifft(&domain, &domain_evals);

    Ok(
        coeffs
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn coset_ifft(evals: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
    let mut domain_evals = vec![];
    for c in &evals {
        domain_evals.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(evals.len()).unwrap();
    let generator = EvaluationDomain::group_gen(&domain);
    let coset_domain = EvaluationDomain::get_coset(&domain, generator).unwrap();
    let coeffs = EvaluationDomain::ifft(&coset_domain, &domain_evals);

    Ok(
        coeffs
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn mul_over_evaluation_domain(a: Vec<BigUint>, b: Vec<BigUint>) -> PyResult<Vec<BigUint>> {
    let mut evals_a = vec![];
    let mut evals_b = vec![];
    for c in &a {
        evals_a.push(Fr::from(c.to_owned()));
    }

    for c in &b {
        evals_b.push(Fr::from(c.to_owned()));
    }

    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(
        evals_a.len() + evals_b.len()
    ).unwrap();
    let result = EvaluationDomain::mul_polynomials_in_evaluation_domain(
        &domain,
        &evals_a,
        &evals_b
    );

    Ok(
        result
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn evaluate_vanishing_polynomial(n: usize, tau: BigUint) -> PyResult<BigUint> {
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(n).ok_or_else(||
        PyValueError::new_err("Domain size is too large")
    )?;

    let result = EvaluationDomain::evaluate_vanishing_polynomial(&domain, Fr::from(tau));
    Ok(result.into())
}

#[pyfunction]
pub fn evaluate_lagrange_coefficients(n: usize, tau: BigUint) -> PyResult<Vec<BigUint>> {
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(n).ok_or_else(||
        PyValueError::new_err("Domain size is too large")
    )?;

    let coeffs = EvaluationDomain::evaluate_all_lagrange_coefficients(&domain, Fr::from(tau));
    Ok(
        coeffs
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}
