use ark_bls12_381::{
    g1::Config, Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::{Pairing, PairingOutput},
    short_weierstrass::Projective,
    AffineRepr, CurveGroup, Group, VariableBaseMSM,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    QuadExtField, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, prelude::*, types::PyType};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[pyclass]
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PointG1 {
    point: G1Projective,
}

#[pymethods]
impl PointG1 {
    #[new]
    pub fn new(x: BigUint, y: BigUint) -> PyResult<Self> {
        let point = G1Affine::new(x.into(), y.into());
        Ok(PointG1 {
            point: point.into(),
        })
    }

    #[getter]
    pub fn x(&self) -> BigUint {
        let affine_points = self.point.into_affine();

        match affine_points.x() {
            None => BigUint::zero(),
            Some(x) => x.to_owned().into(),
        }
    }

    #[getter]
    pub fn y(&self) -> BigUint {
        let affine_points = self.point.into_affine();

        match affine_points.y() {
            None => BigUint::zero(),
            Some(y) => y.to_owned().into(),
        }
    }

    #[getter]
    pub fn generator(&self) -> PyResult<Self> {
        Ok(PointG1 {
            point: G1Projective::generator(),
        })
    }

    fn __str__(&self) -> String {
        let affine_points = self.point.into_affine();
        format!("{}", affine_points.to_string())
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn __add__(&self, other: Self) -> PyResult<Self> {
        Ok(PointG1 {
            point: self.point + other.point,
        })
    }

    pub fn __radd__(&self, other: Self) -> PyResult<Self> {
        self.__add__(other)
    }

    pub fn __sub__(&self, other: Self) -> PyResult<Self> {
        Ok(PointG1 {
            point: self.point - other.point,
        })
    }

    pub fn __rsub__(&self, other: Self) -> PyResult<Self> {
        self.__sub__(other)
    }

    pub fn __neg__(&self) -> PyResult<Self> {
        Ok(PointG1 { point: -self.point })
    }

    pub fn __mul__(&self, other: BigUint) -> PyResult<Self> {
        let scalar = Fr::from(other);
        Ok(PointG1 {
            point: self.point * scalar,
        })
    }

    pub fn __rmul__(&self, other: BigUint) -> PyResult<Self> {
        self.__mul__(other)
    }

    pub fn __eq__(&self, other: Self) -> bool {
        self.point == other.point
    }

    pub fn is_zero(&self) -> PyResult<bool> {
        Ok(self.point.eq(&G1Affine::identity()))
    }

    pub fn to_hex(&self) -> PyResult<String> {
        let mut b = Vec::new();
        let _ = self.point.serialize_compressed(&mut b);
        let hex_string: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
        Ok(hex_string)
    }

    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut b = Vec::new();
        let _ = self.point.serialize_compressed(&mut b);

        Ok(b)
    }

    #[classmethod]
    pub fn from_bytes<'py>(_cls: &Bound<'py, PyType>, hex: Vec<u8>) -> PyResult<Self> {
        match G1Affine::deserialize_compressed(&*hex) {
            Err(e) => Err(PyValueError::new_err(format!(
                "Cannot deserialize point: {}",
                e.to_string()
            ))),
            Ok(point) => Ok(PointG1 {
                point: point.into(),
            }),
        }
    }

    #[classmethod]
    pub fn hash_to_field<'py>(_cls: &Bound<'py, PyType>, dst: Vec<u8>, data: Vec<u8>) -> BigUint {
        use sha2::Sha256;
        let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fq>>::new(&dst);
        let x: Vec<Fq> = hasher.hash_to_field(&data, 1);
        x[0].into()
    }

    #[classmethod]
    pub fn hash_to_curve<'py>(
        _cls: &Bound<'py, PyType>,
        dst: Vec<u8>,
        data: Vec<u8>,
    ) -> PyResult<Self> {
        use sha2::Sha256;
        let hasher = MapToCurveBasedHasher::<
            Projective<Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<Config>,
        >::new(&dst)
        .unwrap();

        let point = hasher.hash(&data).unwrap();
        Ok(PointG1 {
            point: point.into(),
        })
    }

    #[classmethod]
    pub fn from_x<'py>(_cls: &Bound<'py, PyType>, x: BigUint) -> PyResult<Self> {
        match G1Affine::get_point_from_x_unchecked(x.into(), true) {
            Some(e) => {
                if e.is_on_curve() && e.is_in_correct_subgroup_assuming_on_curve() {
                    return Ok(PointG1 { point: e.into() });
                }
                Err(PyValueError::new_err(format!("Point is not on curve")))
            }
            None => Err(PyValueError::new_err(format!("Cannot found point"))),
        }
    }

    #[classmethod]
    pub fn identity<'py>(_cls: &Bound<'py, PyType>) -> PyResult<Self> {
        Ok(PointG1 {
            point: G1Affine::identity().into(),
        })
    }
}

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct PointG2 {
    point: G2Projective,
}

#[pymethods]
impl PointG2 {
    #[new]
    pub fn new(x1: BigUint, x2: BigUint, y1: BigUint, y2: BigUint) -> PyResult<Self> {
        let point_x = QuadExtField::new(x1.into(), x2.into());
        let point_y = QuadExtField::new(y1.into(), y2.into());
        let point = G2Affine::new(point_x, point_y);
        Ok(PointG2 {
            point: point.into(),
        })
    }

    #[getter]
    pub fn x(&self) -> [BigUint; 2] {
        let affine_points = self.point.into_affine();

        match affine_points.x() {
            None => [BigUint::zero(), BigUint::zero()],
            Some(x) => {
                let x1 = x.c0;
                let x2 = x.c1;
                [x1.into(), x2.into()]
            }
        }
    }

    #[getter]
    pub fn y(&self) -> [BigUint; 2] {
        let affine_points = self.point.into_affine();

        match affine_points.y() {
            None => [BigUint::zero(), BigUint::zero()],
            Some(y) => {
                let y1 = y.c0;
                let y2 = y.c1;
                [y1.into(), y2.into()]
            }
        }
    }

    #[getter]
    pub fn generator(&self) -> PyResult<Self> {
        Ok(PointG2 {
            point: G2Projective::generator(),
        })
    }

    fn __str__(&self) -> String {
        format!("({:?}, {:?})", self.x(), self.y())
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn __add__(&self, other: Self) -> PyResult<Self> {
        Ok(PointG2 {
            point: self.point + other.point,
        })
    }

    pub fn __radd__(&self, other: Self) -> PyResult<Self> {
        self.__add__(other)
    }

    pub fn __sub__(&self, other: Self) -> PyResult<Self> {
        Ok(PointG2 {
            point: self.point - other.point,
        })
    }

    pub fn __rsub__(&self, other: Self) -> PyResult<Self> {
        self.__sub__(other)
    }

    pub fn __neg__(&self) -> PyResult<Self> {
        Ok(PointG2 { point: -self.point })
    }

    pub fn __mul__(&self, other: BigUint) -> PyResult<Self> {
        let scalar = Fr::from(other);
        Ok(PointG2 {
            point: self.point * scalar,
        })
    }

    pub fn __rmul__(&self, other: BigUint) -> PyResult<Self> {
        self.__mul__(other)
    }

    pub fn __eq__(&self, other: Self) -> bool {
        self.point == other.point
    }

    pub fn is_zero(&self) -> PyResult<bool> {
        Ok(self.point.eq(&G2Affine::identity()))
    }

    pub fn to_hex(&self) -> PyResult<String> {
        let mut b = Vec::new();
        let _ = self.point.serialize_compressed(&mut b);
        let hex_string: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
        Ok(hex_string)
    }

    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut b = Vec::new();
        let _ = self.point.serialize_compressed(&mut b);

        Ok(b)
    }

    #[classmethod]
    pub fn from_bytes<'py>(_cls: &Bound<'py, PyType>, hex: Vec<u8>) -> PyResult<Self> {
        match G2Affine::deserialize_compressed(&*hex) {
            Err(e) => Err(PyValueError::new_err(format!(
                "Cannot deserialize point: {}",
                e.to_string()
            ))),
            Ok(point) => Ok(PointG2 {
                point: point.into(),
            }),
        }
    }
}

#[pyfunction]
pub fn batch_multi_scalar_g1(
    points: Vec<PointG1>,
    scalars: Vec<BigUint>,
) -> PyResult<Vec<PointG1>> {
    let result: Vec<PointG1> = (&points, &scalars)
        .into_par_iter()
        .map(|(g, s)| PointG1 {
            point: g.point * Fr::from(s.to_owned()),
        })
        .collect();

    Ok(result)
}

#[pyfunction]
pub fn batch_multi_scalar_g2(
    points: Vec<PointG2>,
    scalars: Vec<BigUint>,
) -> PyResult<Vec<PointG2>> {
    let result: Vec<PointG2> = (&points, &scalars)
        .into_par_iter()
        .map(|(g, s)| PointG2 {
            point: g.point * Fr::from(s.to_owned()),
        })
        .collect();

    Ok(result)
}

#[pyfunction]
pub fn multiscalar_mul_g1(points: Vec<PointG1>, scalars: Vec<BigUint>) -> PyResult<PointG1> {
    let mut fr_scalars: Vec<Fr> = vec![];
    for scalar in scalars {
        fr_scalars.push(Fr::from(scalar));
    }
    let mut affine_points: Vec<G1Affine> = vec![];
    for point in points {
        affine_points.push(point.point.into_affine());
    }
    let r = G1Projective::msm(&affine_points, &fr_scalars);
    match r {
        Ok(r) => Ok(PointG1 { point: r }),
        Err(_) => Err(PyValueError::new_err(format!(
            "Number of points and scalars mismatch"
        ))),
    }
}

#[pyfunction]
pub fn multiscalar_mul_g2(points: Vec<PointG2>, scalars: Vec<BigUint>) -> PyResult<PointG2> {
    let mut fr_scalars: Vec<Fr> = vec![];
    for scalar in scalars {
        fr_scalars.push(Fr::from(scalar));
    }
    let mut affine_points: Vec<G2Affine> = vec![];
    for point in points {
        affine_points.push(point.point.into_affine());
    }
    let r = G2Projective::msm(&affine_points, &fr_scalars);
    match r {
        Ok(r) => Ok(PointG2 { point: r }),
        Err(_) => Err(PyValueError::new_err(format!(
            "Number of points and scalars mismatch"
        ))),
    }
}

#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct PointG12 {
    point: PairingOutput<Bls12_381>,
}

#[pymethods]
impl PointG12 {
    pub fn __str__(&self) -> String {
        let mut b: Vec<u8> = vec![];
        self.point.serialize_compressed(&mut b).unwrap();
        format!("{:x?}", b)
    }

    pub fn __repr__(&self) -> String {
        self.__str__()
    }

    pub fn __eq__(&self, other: Self) -> bool {
        self.point == other.point
    }
}

#[pyfunction]
pub fn pairing(a: PointG1, b: PointG2) -> PyResult<PointG12> {
    Ok(PointG12 {
        point: Bls12_381::pairing(a.point, b.point),
    })
}

#[pyfunction]
pub fn multi_pairing(a: Vec<PointG1>, b: Vec<PointG2>) -> PyResult<PointG12> {
    let mut point1: Vec<G1Projective> = vec![];
    let mut point2: Vec<G2Projective> = vec![];
    for p in a {
        point1.push(p.point);
    }
    for p in b {
        point2.push(p.point);
    }
    Ok(PointG12 {
        point: Bls12_381::multi_pairing(point1, point2),
    })
}

#[pyfunction]
pub fn g1() -> PyResult<PointG1> {
    Ok(PointG1 {
        point: G1Projective::generator(),
    })
}

#[pyfunction]
pub fn g2() -> PyResult<PointG2> {
    Ok(PointG2 {
        point: G2Projective::generator(),
    })
}
