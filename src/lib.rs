mod array;
mod bls12_381;
mod bn254;
use pyo3::prelude::*;

fn register_bn254_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let ecc_module = PyModule::new(py, "ec_bn254")?;
    ecc_module.add_class::<bn254::curve::PointG1>()?;
    ecc_module.add_class::<bn254::curve::PointG2>()?;
    ecc_module.add_function(wrap_pyfunction!(bn254::curve::g1, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(bn254::curve::g2, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bn254::curve::batch_multi_scalar_g1,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bn254::curve::batch_multi_scalar_g2,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bn254::curve::multiscalar_mul_g1,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bn254::curve::multiscalar_mul_g2,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(bn254::curve::pairing, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(bn254::curve::multi_pairing, ecc_module)?)?;
    parent_module.add_submodule(ecc_module)?;

    Ok(())
}

fn register_bls12_381_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let ecc_module = PyModule::new(py, "ec_bls12_381")?;
    ecc_module.add_class::<bls12_381::curve::PointG1>()?;
    ecc_module.add_class::<bls12_381::curve::PointG2>()?;
    ecc_module.add_function(wrap_pyfunction!(bls12_381::curve::g1, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(bls12_381::curve::g2, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bls12_381::curve::batch_multi_scalar_g1,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bls12_381::curve::batch_multi_scalar_g2,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bls12_381::curve::multiscalar_mul_g1,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bls12_381::curve::multiscalar_mul_g2,
        ecc_module
    )?)?;
    ecc_module.add_function(wrap_pyfunction!(bls12_381::curve::pairing, ecc_module)?)?;
    ecc_module.add_function(wrap_pyfunction!(
        bls12_381::curve::multi_pairing,
        ecc_module
    )?)?;
    parent_module.add_submodule(ecc_module)?;

    Ok(())
}

fn register_polynomial_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let poly_bn254_module = PyModule::new(py, "polynomial_bn254")?;
    poly_bn254_module.add_class::<bn254::polynomial::PolynomialRing>()?;
    poly_bn254_module.add_function(wrap_pyfunction!(bn254::polynomial::fft, poly_bn254_module)?)?;
    poly_bn254_module.add_function(wrap_pyfunction!(
        bn254::polynomial::ifft,
        poly_bn254_module
    )?)?;
    poly_bn254_module.add_function(wrap_pyfunction!(
        bn254::polynomial::evaluate_vanishing_polynomial,
        poly_bn254_module
    )?)?;

    let poly_bls12_381_module = PyModule::new(py, "polynomial_bls12_381")?;
    poly_bls12_381_module.add_class::<bls12_381::polynomial::PolynomialRing>()?;
    poly_bls12_381_module.add_function(wrap_pyfunction!(
        bls12_381::polynomial::fft,
        poly_bls12_381_module
    )?)?;
    poly_bls12_381_module.add_function(wrap_pyfunction!(
        bls12_381::polynomial::ifft,
        poly_bls12_381_module
    )?)?;
    poly_bls12_381_module.add_function(wrap_pyfunction!(
        bls12_381::polynomial::evaluate_vanishing_polynomial,
        poly_bls12_381_module
    )?)?;

    parent_module.add_submodule(poly_bn254_module)?;
    parent_module.add_submodule(poly_bls12_381_module)?;

    Ok(())
}

fn register_array_module(py: Python, parent_module: &PyModule) -> PyResult<()> {
    let array_module = PyModule::new(py, "array")?;
    array_module.add_function(wrap_pyfunction!(array::dot_product, array_module)?)?;
    array_module.add_function(wrap_pyfunction!(array::transpose, array_module)?)?;

    parent_module.add_submodule(array_module)?;

    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn _algebra(_py: Python, m: &PyModule) -> PyResult<()> {
    register_bn254_module(_py, m)?;
    register_bls12_381_module(_py, m)?;
    register_polynomial_module(_py, m)?;
    register_array_module(_py, m)?;
    Ok(())
}