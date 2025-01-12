use ark_bls12_381::Fr;
use ark_poly::{
    multivariate::{ SparsePolynomial, SparseTerm, Term },
    polynomial::univariate::DensePolynomial,
    univariate,
    DenseMVPolynomial,
    DenseUVPolynomial,
    EvaluationDomain,
    GeneralEvaluationDomain,
    Polynomial,
};
use ark_ff::Zero;
use num_bigint::BigUint;
use pyo3::{
    exceptions::{ PyRuntimeError, PyValueError },
    prelude::*,
    types::{ PyDict, PyList, PyTuple },
};
use rayon::prelude::*;

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialRing {
    poly: PolynomialKind,
    domain: GeneralEvaluationDomain<Fr>,
}

#[derive(Clone, Debug, PartialEq)]
enum PolynomialKind {
    Univariate(DensePolynomial<Fr>),
    Multivariate(SparsePolynomial<Fr, SparseTerm>),
}

#[pymethods]
impl PolynomialRing {
    #[new]
    pub fn new(
        num_vars: usize,
        coeffs: Vec<(BigUint, Vec<(usize, usize)>)>,
        size: usize
    ) -> PyResult<Self> {
        if num_vars > 1 {
            let mut terms: Vec<(Fr, SparseTerm)> = vec![];
            for (v, term) in coeffs.clone() {
                let t = SparseTerm::new(term);
                terms.push((Fr::from(v), t));
            }
            let poly = PolynomialKind::Multivariate(
                SparsePolynomial::from_coefficients_vec(num_vars, terms)
            );

            let domain = EvaluationDomain::new(size).unwrap();
            Ok(PolynomialRing { poly, domain })
        } else {
            let mut fp_coeffs = vec![];
            for (coeff, _) in coeffs.clone() {
                fp_coeffs.push(Fr::from(coeff));
            }
            let poly = PolynomialKind::Univariate(
                DensePolynomial::from_coefficients_vec(fp_coeffs)
            );
            let domain = EvaluationDomain::new(size).unwrap();
            Ok(PolynomialRing { poly, domain })
        }
    }

    pub fn __str__(&self) -> String {
        match &self.poly {
            PolynomialKind::Univariate(poly) => {
                let degree = poly.coeffs.len() - 1;
                let mut str: String = String::new();
                for (i, &coeff) in poly.coeffs.iter().rev().enumerate() {
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
            PolynomialKind::Multivariate(poly) => {
                poly.terms
                    .iter()
                    .map(|(coeff, monomial)| {
                        let mut term = String::new();

                        // Add coefficient (skip if it's 1 and not the only term)
                        if *coeff != Fr::from(1u64) || monomial.is_empty() {
                            term.push_str(&format!("{}", coeff));
                        }

                        // Add variable terms
                        for (var, exp) in monomial.iter() {
                            if *exp > 0 {
                                term.push_str(&format!("x{}", var));
                                if *exp > 1 {
                                    term.push_str(&format!("^{}", exp));
                                }
                            }
                        }

                        term
                    })
                    .rev()
                    .collect::<Vec<String>>()
                    .join(" + ")
            }
        }
    }

    pub fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn __eq__(&self, other: Self) -> bool {
        match (&self.poly, &other.poly) {
            // Compare univariate polynomials
            (PolynomialKind::Univariate(p1), PolynomialKind::Univariate(p2)) => p1 == p2,

            // Compare multivariate polynomials
            (PolynomialKind::Multivariate(p1), PolynomialKind::Multivariate(p2)) => p1 == p2,

            // Different types cannot be equal
            _ => false,
        }
    }

    pub fn coeffs(&self, py: Python) -> PyResult<PyObject> {
        match &self.poly {
            PolynomialKind::Univariate(poly) => {
                let mut r: Vec<BigUint> = vec![];
                for c in poly.coeffs.iter() {
                    r.push(c.to_owned().into());
                }
                Ok(PyList::new(py, r).into())
            }
            PolynomialKind::Multivariate(poly) => {
                let result = PyDict::new(py);
                for (c, term) in poly.terms.iter() {
                    let mut terms: Vec<usize> = vec![0; poly.num_vars];
                    term.iter().for_each(|(v, power)| {
                        terms[*v] = *power;
                    });
                    let key = PyTuple::new(py, terms);
                    result.set_item::<&PyTuple, BigUint>(key, c.to_owned().into())?;
                }

                Ok(result.into())
            }
        }
    }

    pub fn degree(&self) -> PyResult<BigUint> {
        match &self.poly {
            PolynomialKind::Univariate(poly) => Ok(poly.degree().into()),
            PolynomialKind::Multivariate(poly) => Ok(poly.degree().into()),
        }
    }

    pub fn __add__(&self, other: &PyAny) -> PyResult<Self> {
        if let Ok(other_int) = other.extract::<BigUint>() {
            match &self.poly {
                PolynomialKind::Univariate(poly) => {
                    let mut coeffs = poly.coeffs.clone();
                    let adder: Fr = other_int.into();
                    coeffs[0] = coeffs[0] + adder;

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(
                            DensePolynomial::from_coefficients_vec(coeffs.to_vec())
                        ),
                        domain: self.domain,
                    })
                }
                PolynomialKind::Multivariate(poly) => {
                    let mut terms = poly.terms.clone();
                    let mut constant_added = false;
                    let adder: Fr = other_int.into();

                    for (coeff, monomial) in &mut terms {
                        if monomial.is_empty() {
                            *coeff += adder;
                            constant_added = true;
                            break;
                        }
                    }

                    if !constant_added {
                        terms.push((adder, SparseTerm::new(vec![])));
                    }

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Multivariate(
                            SparsePolynomial::from_coefficients_vec(poly.num_vars, terms.to_vec())
                        ),
                        domain: self.domain,
                    })
                }
            }
        } else if let Ok(other_poly) = other.extract::<PolynomialRing>() {
            match (&self.poly, &other_poly.poly) {
                (PolynomialKind::Univariate(poly), PolynomialKind::Univariate(other)) => {
                    let result = poly + other;
                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(result),
                        domain: self.domain,
                    })
                }
                (PolynomialKind::Multivariate(poly), PolynomialKind::Multivariate(other)) => {
                    let result = poly + other;
                    Ok(PolynomialRing {
                        poly: PolynomialKind::Multivariate(result),
                        domain: self.domain,
                    })
                }
                _ =>
                    Err(
                        pyo3::exceptions::PyTypeError::new_err(
                            format!("Unsupported type for addition: {:?}", other.get_type().name())
                        )
                    ),
            }
        } else {
            Err(
                pyo3::exceptions::PyTypeError::new_err(
                    format!("Unsupported type for addition: {:?}", other.get_type().name())
                )
            )
        }
    }

    pub fn __radd__(&self, other: &PyAny) -> PyResult<Self> {
        self.__add__(other)
    }

    pub fn __neg__(&self) -> PyResult<Self> {
        match &self.poly {
            PolynomialKind::Univariate(poly) =>
                Ok(PolynomialRing {
                    poly: PolynomialKind::Univariate(-poly.clone()),
                    domain: self.domain,
                }),
            PolynomialKind::Multivariate(poly) =>
                Ok(PolynomialRing {
                    poly: PolynomialKind::Multivariate(-poly.clone()),
                    domain: self.domain,
                }),
        }
    }

    pub fn __sub__(&self, other: &PyAny) -> PyResult<Self> {
        if let Ok(other_int) = other.extract::<BigUint>() {
            match &self.poly {
                PolynomialKind::Univariate(poly) => {
                    let mut coeffs = poly.coeffs.clone();
                    let substractor: Fr = other_int.into();
                    coeffs[0] = coeffs[0] - substractor;

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(
                            DensePolynomial::from_coefficients_vec(coeffs.to_vec())
                        ),
                        domain: self.domain,
                    })
                }
                PolynomialKind::Multivariate(poly) => {
                    let mut terms = poly.terms.clone();
                    let mut constant_added = false;
                    let substractor: Fr = other_int.into();

                    for (coeff, monomial) in &mut terms {
                        if monomial.is_empty() {
                            *coeff -= substractor;
                            constant_added = true;
                            break;
                        }
                    }

                    if !constant_added {
                        terms.push((-substractor, SparseTerm::new(vec![])));
                    }

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Multivariate(
                            SparsePolynomial::from_coefficients_vec(poly.num_vars, terms.to_vec())
                        ),
                        domain: self.domain,
                    })
                }
            }
        } else if let Ok(other_poly) = other.extract::<PolynomialRing>() {
            match (&self.poly, &other_poly.poly) {
                (PolynomialKind::Univariate(poly), PolynomialKind::Univariate(other)) => {
                    let result = poly - other;
                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(result),
                        domain: self.domain,
                    })
                }
                (PolynomialKind::Multivariate(poly), PolynomialKind::Multivariate(other)) => {
                    let result = poly - other;
                    Ok(PolynomialRing {
                        poly: PolynomialKind::Multivariate(result),
                        domain: self.domain,
                    })
                }
                _ =>
                    Err(
                        pyo3::exceptions::PyTypeError::new_err(
                            format!("Unsupported type for addition: {:?}", other.get_type().name())
                        )
                    ),
            }
        } else {
            Err(
                pyo3::exceptions::PyTypeError::new_err(
                    format!("Unsupported type for addition: {:?}", other.get_type().name())
                )
            )
        }
    }

    pub fn __mul__(&self, other: &PyAny) -> PyResult<Self> {
        if let Ok(other_int) = other.extract::<BigUint>() {
            match &self.poly {
                PolynomialKind::Univariate(poly) => {
                    let coeffs = poly.coeffs.clone();
                    let mult: Fr = other_int.into();

                    let new_coeffs: Vec<Fr> = coeffs
                        .par_iter()
                        .map(|&e| e * mult)
                        .collect();

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(
                            DensePolynomial::from_coefficients_vec(new_coeffs.to_vec())
                        ),
                        domain: self.domain,
                    })
                }
                PolynomialKind::Multivariate(poly) => {
                    let terms = poly.terms.clone();
                    let mult: Fr = other_int.into();

                    let new_terms: Vec<(Fr, SparseTerm)> = terms
                        .par_iter()
                        .map(|(coeff, term)| (coeff * &mult, term.clone()))
                        .collect();

                    Ok(PolynomialRing {
                        poly: PolynomialKind::Multivariate(
                            SparsePolynomial::from_coefficients_vec(poly.num_vars, new_terms)
                        ),
                        domain: self.domain,
                    })
                }
            }
        } else if let Ok(other_poly) = other.extract::<PolynomialRing>() {
            match (&self.poly, &other_poly.poly) {
                (PolynomialKind::Univariate(poly), PolynomialKind::Univariate(other)) => {
                    Ok(PolynomialRing {
                        poly: PolynomialKind::Univariate(DensePolynomial::naive_mul(&poly, &other)),
                        domain: self.domain,
                    })
                }
                (PolynomialKind::Multivariate(poly), PolynomialKind::Multivariate(other)) => {
                    if poly.is_zero() || other.is_zero() {
                        Ok(PolynomialRing {
                            poly: PolynomialKind::Multivariate(SparsePolynomial::zero()),
                            domain: self.domain,
                        })
                    } else {
                        let mut result_terms = Vec::new();
                        for (cur_coeff, cur_term) in poly.terms.iter() {
                            for (other_coeff, other_term) in other.terms.iter() {
                                let mut term = cur_term.to_vec();
                                term.extend(other_term.to_vec());
                                result_terms.push((
                                    *cur_coeff * *other_coeff,
                                    SparseTerm::new(term),
                                ));
                            }
                        }
                        let result = SparsePolynomial::from_coefficients_slice(
                            poly.num_vars,
                            result_terms.as_slice()
                        );

                        Ok(PolynomialRing {
                            poly: PolynomialKind::Multivariate(result),
                            domain: self.domain,
                        })
                    }
                }
                _ =>
                    Err(
                        pyo3::exceptions::PyTypeError::new_err(
                            format!(
                                "Unsupported type for multiplication: {:?}",
                                other.get_type().name()
                            )
                        )
                    ),
            }
        } else {
            Err(
                pyo3::exceptions::PyTypeError::new_err(
                    format!("Unsupported type for multiplication: {:?}", other.get_type().name())
                )
            )
        }
    }

    pub fn __rmul__(&self, other: &PyAny) -> PyResult<Self> {
        self.__mul__(other)
    }

    pub fn __truediv__(&self, other: Self) -> PyResult<[PolynomialRing; 2]> {
        match (&self.poly, &other.poly) {
            (PolynomialKind::Univariate(poly), PolynomialKind::Univariate(other)) => {
                let result = univariate::DenseOrSparsePolynomial::divide_with_q_and_r(
                    &poly.clone().into(),
                    &other.into()
                );

                match result {
                    Some((quotient, remainder)) => {
                        let q_coeffs = quotient.coeffs.len();
                        let r_coeffs = remainder.coeffs.len();
                        Ok(
                            (
                                PolynomialRing {
                                    poly: PolynomialKind::Univariate(quotient),
                                    domain: EvaluationDomain::new(q_coeffs).unwrap(),
                                },
                                PolynomialRing {
                                    poly: PolynomialKind::Univariate(remainder),
                                    domain: EvaluationDomain::new(r_coeffs).unwrap(),
                                },
                            ).into()
                        )
                    }
                    None => Err(PyRuntimeError::new_err("Polynomial division error")),
                }
            }
            (PolynomialKind::Multivariate(_), PolynomialKind::Multivariate(_)) => {
                Err(pyo3::exceptions::PyTypeError::new_err(format!("Not supported")))
            }
            _ =>
                Err(
                    pyo3::exceptions::PyTypeError::new_err(
                        format!("Can only divide same n-variate polynomial")
                    )
                ),
        }
    }

    pub fn is_zero(&self) -> bool {
        match &self.poly {
            PolynomialKind::Univariate(poly) => poly.coeffs.len() == 0,
            PolynomialKind::Multivariate(poly) => poly.terms.len() == 0,
        }
    }

    pub fn multiply_by_vanishing_poly(&self) -> PyResult<PolynomialRing> {
        match &self.poly {
            PolynomialKind::Univariate(poly) => {
                let result = PolynomialKind::Univariate(
                    DensePolynomial::mul_by_vanishing_poly(poly, self.domain)
                );

                Ok(PolynomialRing { poly: result, domain: self.domain })
            }
            PolynomialKind::Multivariate(_) => {
                Err(
                    pyo3::exceptions::PyTypeError::new_err(
                        format!("Can only multiply univariate polynomial")
                    )
                )
            }
        }
    }

    pub fn divide_by_vanishing_poly(&self) -> PyResult<[PolynomialRing; 2]> {
        match &self.poly {
            PolynomialKind::Univariate(poly) => {
                let result = DensePolynomial::divide_by_vanishing_poly(&poly, self.domain);
                match result {
                    Some((quotient, remainder)) =>
                        Ok(
                            (
                                PolynomialRing {
                                    poly: PolynomialKind::Univariate(quotient),
                                    domain: self.domain,
                                },
                                PolynomialRing {
                                    poly: PolynomialKind::Univariate(remainder),
                                    domain: self.domain,
                                },
                            ).into()
                        ),
                    None => Err(PyRuntimeError::new_err("Cannot divided by vanishing poly")),
                }
            }
            PolynomialKind::Multivariate(_) => {
                Err(
                    pyo3::exceptions::PyTypeError::new_err(
                        format!("Can only divide univariate polynomial")
                    )
                )
            }
        }
    }

    pub fn __call__(&self, point: &PyAny) -> PyResult<BigUint> {
        match &self.poly {
            PolynomialKind::Univariate(poly) => {
                if let Ok(point) = point.extract::<BigUint>() {
                    let eval = DensePolynomial::evaluate(&poly, &Fr::from(point));
                    Ok(eval.into())
                } else {
                    Err(
                        pyo3::exceptions::PyTypeError::new_err(
                            format!("Univariate polynomial evaluation only accept int")
                        )
                    )
                }
            }
            PolynomialKind::Multivariate(poly) => {
                if let Ok(point) = point.extract::<Vec<BigUint>>() {
                    let points: Vec<Fr> = point
                        .iter()
                        .map(|x| Fr::from(x.to_owned()))
                        .collect();
                    let eval = SparsePolynomial::evaluate(&poly, &points);
                    Ok(eval.into())
                } else {
                    Err(
                        pyo3::exceptions::PyTypeError::new_err(
                            format!("Multivariate polynomial evaluation only accept list of int")
                        )
                    )
                }
            }
        }
    }
}

#[pyfunction]
pub fn get_nth_root_of_unity(domain: usize, i: usize) -> PyResult<BigUint> {
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(domain).unwrap();

    Ok(EvaluationDomain::element(&domain, i).into())
}

#[pyfunction]
pub fn get_all_root_of_unity(domain: usize) -> PyResult<Vec<BigUint>> {
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(domain).unwrap();

    Ok(
        EvaluationDomain::elements(&domain)
            .into_iter()
            .map(|e| e.into())
            .collect()
    )
}

#[pyfunction]
pub fn fft(coeffs: Vec<BigUint>, size: usize) -> PyResult<Vec<BigUint>> {
    let mut domain_coeff = vec![];
    for c in &coeffs {
        domain_coeff.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(size).unwrap();
    let evals = EvaluationDomain::fft(&domain, &domain_coeff);

    Ok(
        evals
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn coset_fft(coeffs: Vec<BigUint>, size: usize) -> PyResult<Vec<BigUint>> {
    let mut domain_coeff = vec![];
    for c in &coeffs {
        domain_coeff.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(size).unwrap();
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
pub fn ifft(evals: Vec<BigUint>, size: usize) -> PyResult<Vec<BigUint>> {
    let mut domain_evals = vec![];
    for c in &evals {
        domain_evals.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(size).unwrap();
    let coeffs = EvaluationDomain::ifft(&domain, &domain_evals);

    Ok(
        coeffs
            .par_iter()
            .map(|x| x.to_owned().into())
            .collect()
    )
}

#[pyfunction]
pub fn coset_ifft(evals: Vec<BigUint>, size: usize) -> PyResult<Vec<BigUint>> {
    let mut domain_evals = vec![];
    for c in &evals {
        domain_evals.push(Fr::from(c.to_owned()));
    }
    let domain: GeneralEvaluationDomain<Fr> = EvaluationDomain::new(size).unwrap();
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
pub fn add_over_evaluation_domain(
    size: usize,
    a: Vec<BigUint>,
    b: Vec<BigUint>
) -> PyResult<Vec<BigUint>> {
    let mut evals_a = vec![Fr::from(0); size];
    let mut evals_b = vec![Fr::from(0); size];
    for i in 0..size {
        evals_a[i] = Fr::from(a[i].to_owned());
        evals_b[i] = Fr::from(b[i].to_owned());
    }

    let result: Vec<Fr> = evals_a
        .par_iter()
        .zip(evals_b)
        .map(|(a, b)| *a + b)
        .collect();

    Ok(result.into_iter().map(Into::into).collect())
}

#[pyfunction]
pub fn mul_over_evaluation_domain(
    size: usize,
    a: Vec<BigUint>,
    b: Vec<BigUint>
) -> PyResult<Vec<BigUint>> {
    let mut evals_a = vec![Fr::from(0); size];
    let mut evals_b = vec![Fr::from(0); size];
    for i in 0..size {
        if i < a.len() {
            evals_a[i] = Fr::from(a[i].to_owned());
        }

        if i < b.len() {
            evals_b[i] = Fr::from(b[i].to_owned());
        }
    }

    let result: Vec<Fr> = evals_a
        .par_iter()
        .zip(evals_b)
        .map(|(a, b)| *a * b)
        .collect();

    Ok(result.into_iter().map(Into::into).collect())
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
