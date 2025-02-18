use ark_ff::Zero;
use num_bigint::BigUint;
use pyo3::{ prelude::*, types::{ PyDict, PyInt } };
use std::{ collections::{ HashMap, HashSet, VecDeque }, error::Error };

use super::{ plonkish, r1cs::{ compile, get_witness_vector } };

#[derive(Debug)]
pub enum Gate {
    Input(String),
    Add(Box<Node>, Box<Node>),
    Sub(Box<Node>, Box<Node>),
    Mul(Box<Node>, Box<Node>),
    Div(Box<Node>, Box<Node>),
    Neg(Box<Node>),
    Const(BigUint),
}

#[derive(Debug)]
pub struct Node {
    pub gate: Gate,
    value: Option<BigUint>,
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Node {
            gate: match &self.gate {
                Gate::Input(name) => Gate::Input(name.clone()),
                Gate::Add(left, right) => Gate::Add(left.clone(), right.clone()),
                Gate::Sub(left, right) => Gate::Sub(left.clone(), right.clone()),
                Gate::Mul(left, right) => Gate::Mul(left.clone(), right.clone()),
                Gate::Div(left, right) => Gate::Div(left.clone(), right.clone()),
                Gate::Neg(left) => Gate::Neg(left.clone()),
                Gate::Const(val) => Gate::Const(val.clone()),
            },
            value: self.value.clone(),
        }
    }
}

impl Node {
    pub fn new(gate: Gate) -> Self {
        Node { gate, value: None }
    }

    pub fn empty() -> Self {
        Node { gate: Gate::Const(BigUint::zero()), value: None }
    }

    pub fn evaluate(
        &mut self,
        inputs: &HashMap<String, BigUint>,
        modulus: &BigUint
    ) -> Result<BigUint, Box<dyn Error>> {
        if let Some(val) = self.value.clone() {
            return Ok(val);
        }

        let result = match &mut self.gate {
            Gate::Input(name) =>
                match inputs.get(name) {
                    Some(v) => v.clone(),
                    None => {
                        return Err("Missing one or more variable on evaluation".into());
                    }
                }
            Gate::Add(left, right) =>
                (left.evaluate(inputs, modulus)? + right.evaluate(inputs, modulus)?) % modulus,
            Gate::Sub(left, right) => {
                let l = left.evaluate(inputs, modulus)?;
                let r = right.evaluate(inputs, modulus)?;
                if l < r {
                    modulus - (r - l)
                } else {
                    (l - r) % modulus
                }
            }

            Gate::Mul(left, right) =>
                (left.evaluate(inputs, modulus)? * right.evaluate(inputs, modulus)?) % modulus,
            Gate::Div(left, right) => {
                let r = right.evaluate(inputs, modulus)?.modinv(modulus);
                match r {
                    Some(v) => { left.evaluate(inputs, modulus)? * v }
                    None => {
                        return Err("Modular inverse not found".into());
                    }
                }
            }

            Gate::Neg(node) => modulus - node.evaluate(inputs, modulus)?,
            Gate::Const(val) => val.clone(),
        };

        self.value = Some(result.clone());
        Ok(result % modulus)
    }

    pub fn to_expression(&self) -> String {
        match &self.gate {
            Gate::Input(name) => name.clone(),
            Gate::Add(left, right) =>
                format!("({} + {})", left.to_expression(), right.to_expression()),
            Gate::Sub(left, right) =>
                format!("({} - {})", left.to_expression(), right.to_expression()),
            Gate::Mul(left, right) =>
                format!("{} * {}", left.to_expression(), right.to_expression()),
            Gate::Div(left, right) =>
                format!("{} / {}", left.to_expression(), right.to_expression()),
            Gate::Neg(left) => format!("-({})", left.to_expression()),
            Gate::Const(val) => val.to_string(),
        }
    }

    pub fn isolate_term(&self, target: &str, right: &Node) -> Result<Node, Box<dyn Error>> {
        match &self.gate {
            Gate::Add(left, right_node) => {
                if left.contains_target(target) {
                    // Move right_node to the RHS: right - right_node
                    let new_rhs = Node::new(Gate::Sub(Box::new(right.clone()), right_node.clone()));
                    left.isolate_term(target, &new_rhs)
                } else if right_node.contains_target(target) {
                    // Move left to the RHS: right - left
                    let new_rhs = Node::new(Gate::Sub(Box::new(right.clone()), left.clone()));
                    right_node.isolate_term(target, &new_rhs)
                } else {
                    Err("Target term not found in Add gate".into())
                }
            }
            Gate::Sub(left, right_node) => {
                if left.contains_target(target) {
                    // Move -right_node to the RHS: right + right_node
                    let new_rhs = Node::new(Gate::Add(Box::new(right.clone()), right_node.clone()));
                    left.isolate_term(target, &new_rhs)
                } else if right_node.contains_target(target) {
                    // Move left to the RHS: right - left
                    let new_rhs = Node::new(Gate::Sub(Box::new(right.clone()), left.clone()));
                    right_node.isolate_term(target, &new_rhs)
                } else {
                    Err("Target term not found in Sub gate".into())
                }
            }
            Gate::Mul(left, right_node) => {
                if left.contains_target(target) {
                    // Move right_node to the RHS: right / right_node
                    let new_rhs = Node::new(Gate::Div(Box::new(right.clone()), right_node.clone()));
                    left.isolate_term(target, &new_rhs)
                } else if right_node.contains_target(target) {
                    // Move left to the RHS: right / left
                    let new_rhs = Node::new(Gate::Div(Box::new(right.clone()), left.clone()));
                    right_node.isolate_term(target, &new_rhs)
                } else {
                    Err("Target term not found in Mul gate".into())
                }
            }
            Gate::Input(name) if name == target => Ok(right.clone()),
            _ =>
                Err(
                    format!(
                        "Unable to rearrange non-linear equation: {} = {}",
                        self.to_expression(),
                        right.to_expression()
                    ).into()
                ),
        }
    }

    /// Checks if the target term exists in the current node or its children.
    fn contains_target(&self, target: &str) -> bool {
        match &self.gate {
            Gate::Input(name) => name == target,
            | Gate::Add(left, right)
            | Gate::Sub(left, right)
            | Gate::Mul(left, right)
            | Gate::Div(left, right) => {
                left.contains_target(target) || right.contains_target(target)
            }
            Gate::Neg(node) => node.contains_target(target),
            _ => false,
        }
    }

    fn extract_vars(&self, var_result: &mut Vec<String>) {
        match &self.gate {
            Gate::Input(name) => var_result.push(name.to_string()),
            | Gate::Add(left, right)
            | Gate::Sub(left, right)
            | Gate::Mul(left, right)
            | Gate::Div(left, right) => {
                left.extract_vars(var_result);
                right.extract_vars(var_result);
            }
            Gate::Neg(node) => node.extract_vars(var_result),
            _ => {}
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct Equation {
    pub lhs: Node,
    pub rhs: Node,
}

#[pymethods]
impl Equation {
    #[new]
    pub fn new(left: PyRef<Field>, right: PyRef<Field>) -> Self {
        Equation { lhs: left.inner.clone(), rhs: right.inner.clone() }
    }

    pub fn evaluate(
        &mut self,
        inputs: HashMap<String, BigUint>,
        modulus: BigUint
    ) -> (BigUint, BigUint) {
        let left = self.lhs.evaluate(&inputs, &modulus).unwrap();
        let right = self.rhs.evaluate(&inputs, &modulus).unwrap();

        (left, right)
    }

    pub fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{} = {}", self.lhs.to_expression(), self.rhs.to_expression()))
    }

    pub fn swap(&mut self) {
        std::mem::swap(&mut self.lhs, &mut self.rhs);
    }
}

#[pyclass]
pub struct Field {
    pub inner: Node,
}

#[pymethods]
impl Field {
    #[new]
    pub fn new(var: String) -> Self {
        Field {
            inner: Node::new(Gate::Input(var)),
        }
    }

    pub fn evaluate(&mut self, inputs: HashMap<String, BigUint>, modulus: BigUint) -> BigUint {
        self.inner.evaluate(&inputs, &modulus).unwrap()
    }

    fn __add__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for +"));
        };

        Ok(Field {
            inner: Node::new(Gate::Add(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __radd__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for +"));
        };

        Ok(Field {
            inner: Node::new(Gate::Add(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __sub__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for -"));
        };

        Ok(Field {
            inner: Node::new(Gate::Sub(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __rsub__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for -"));
        };

        Ok(Field {
            inner: Node::new(Gate::Sub(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __neg__(&self) -> PyResult<Self> {
        Ok(Field {
            inner: Node::new(Gate::Neg(Box::new(self.inner.clone()))),
        })
    }

    fn __mul__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for *"));
        };

        Ok(Field {
            inner: Node::new(Gate::Mul(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __rmul__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for *"));
        };

        Ok(Field {
            inner: Node::new(Gate::Mul(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __floordiv__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for /"));
        };

        Ok(Field {
            inner: Node::new(Gate::Div(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __truediv__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Self> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for //"));
        };

        Ok(Field {
            inner: Node::new(Gate::Div(Box::new(lhs.inner.clone()), Box::new(rhs_node))),
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(self.inner.to_expression())
    }

    fn __str__(&self) -> PyResult<String> {
        self.__repr__()
    }

    fn __eq__(lhs: PyRef<Self>, rhs: &PyAny) -> PyResult<Equation> {
        let rhs_node = if let Ok(rhs_int) = rhs.extract::<BigUint>() {
            Node::new(Gate::Const(rhs_int))
        } else if let Ok(rhs_node) = rhs.extract::<PyRef<Self>>() {
            rhs_node.inner.clone()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err("Unsupported operand type for =="));
        };

        let left = lhs.inner.clone();
        Ok(Equation { lhs: left, rhs: rhs_node })
    }
}

#[derive(Clone)]
pub enum SequenceRow {
    Constraint(Equation),
    Assignment(String, Node),
    Hint(String, PyObject, Vec<String>),
}

#[pyclass]
pub struct ConstraintSystem {
    pub constraints: Vec<Equation>,
    pub vars: HashMap<String, BigUint>,
    pub modulus: BigUint,
    pub public_vars: Vec<String>,
    sequence: Vec<SequenceRow>,
    assigned: HashSet<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        ConstraintSystem {
            constraints: vec![],
            vars: HashMap::default(),
            public_vars: vec![],
            modulus: BigUint::default(),
            sequence: vec![],
            assigned: HashSet::new(),
            inputs: vec![],
            outputs: vec![],
        }
    }
}

impl ConstraintSystem {
    fn add_var(&mut self, node: &Node) {
        match &node.gate {
            Gate::Input(name) => {
                self.vars.entry(name.to_string()).or_insert(BigUint::default());
            }
            | Gate::Add(left, right)
            | Gate::Sub(left, right)
            | Gate::Mul(left, right)
            | Gate::Div(left, right) => {
                self.add_var(&left.clone());
                self.add_var(&right.clone());
            }
            Gate::Neg(node) => self.add_var(&node.clone()),
            Gate::Const(_) => {}
        }
    }

    fn find_unassigned_var(&mut self, node: &Node) -> Option<String> {
        match &node.gate {
            Gate::Input(name) => {
                return Some(name.to_string());
            }
            | Gate::Add(left, right)
            | Gate::Sub(left, right)
            | Gate::Mul(left, right)
            | Gate::Div(left, right) => {
                let result = self
                    .find_unassigned_var(&left.clone())
                    .or_else(|| self.find_unassigned_var(&right.clone()));
                return result;
            }
            Gate::Neg(node) => self.find_unassigned_var(&node.clone()),
            Gate::Const(_) => { None }
        }
    }
}

#[pymethods]
impl ConstraintSystem {
    #[new]
    pub fn new(inputs: Vec<String>, outputs: Vec<String>, modulus: BigUint) -> Self {
        let assigned: HashSet<String> = HashSet::from_iter(inputs.clone());

        ConstraintSystem {
            constraints: vec![],
            vars: HashMap::default(),
            public_vars: vec![],
            modulus,
            sequence: vec![],
            assigned,
            inputs,
            outputs,
        }
    }

    #[getter]
    pub fn constraints(&self) -> Vec<Equation> {
        self.constraints.clone()
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn num_witness(&self) -> usize {
        self.vars.len()
    }

    #[getter]
    pub fn public_vars(&self) -> Vec<String> {
        self.public_vars.clone()
    }

    pub fn add_variable(&mut self, var: PyRef<Field>) {
        self.add_var(&var.inner);
    }

    pub fn set_public(&mut self, var: &PyAny) -> PyResult<()> {
        if let Ok(v) = var.extract::<String>() {
            self.public_vars.push(v);
            Ok(())
        } else if let Ok(v) = var.extract::<PyRef<Field>>() {
            match &v.inner.gate {
                Gate::Input(name) => {
                    self.public_vars.push(name.to_string());
                    Ok(())
                }
                _ => Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("Invalid expression")),
            }
        } else if let Ok(v) = var.extract::<Vec<PyRef<Field>>>() {
            for node in v {
                match &node.inner.gate {
                    Gate::Input(name) => {
                        self.public_vars.push(name.to_string());
                    }
                    _ => {
                        return Err(
                            PyErr::new::<pyo3::exceptions::PyTypeError, _>("Invalid expression")
                        );
                    }
                }
            }
            Ok(())
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>("Invalid expression"))
        }
    }

    pub fn add_constraint(&mut self, mut constraint: Equation) {
        if
            matches!(constraint.rhs.gate, Gate::Input(_) | Gate::Const(_)) &&
            !matches!(constraint.lhs.gate, Gate::Input(_))
        {
            constraint.swap();
        }

        match constraint.lhs.gate {
            Gate::Input(ref name) => {
                if self.assigned.insert(name.to_string()) {
                    self.sequence.push(
                        SequenceRow::Assignment(name.to_string(), constraint.rhs.clone())
                    );
                }
            }
            _ => {
                if let Some(unassigned) = self.find_unassigned_var(&constraint.lhs) {
                    if self.assigned.insert(unassigned.clone()) {
                        let new_eq = constraint.lhs
                            .isolate_term(&unassigned, &constraint.rhs)
                            .unwrap();
                        self.sequence.push(SequenceRow::Assignment(unassigned, new_eq));
                    }
                }
            }
        }

        self.add_var(&constraint.lhs);
        self.add_var(&constraint.rhs);

        self.constraints.push(constraint.clone());
        self.sequence.push(SequenceRow::Constraint(constraint));
    }

    pub fn unsafe_assign(
        &mut self,
        target: &Field,
        func: PyObject,
        args: Vec<String>
    ) -> PyResult<()> {
        match &target.inner.gate {
            Gate::Input(name) => {
                self.sequence.push(SequenceRow::Hint(name.to_string(), func, args));
                return Ok(());
            }
            _ =>
                Err(
                    PyErr::new::<pyo3::exceptions::PyTypeError, _>("Invalid assignment expression")
                ),
        }
    }

    pub fn evaluate(&mut self, py: Python, inputs: HashMap<String, BigUint>) -> PyResult<()> {
        let mut evaluated: HashSet<String> = Default::default();
        for key in self.inputs.iter() {
            let default = inputs
                .get(key)
                .expect(
                    &format!("All inputs and outputs variable must present: {} is missing", key)
                );
            self.vars.entry(key.to_string()).and_modify(|v| {
                *v = default.to_owned();
            });
            evaluated.insert(key.to_string());
        }

        let mut queue: VecDeque<_> = self.sequence.iter().cloned().collect();
        let max_loop = self.sequence.len() * 256;
        let mut current_loop = 0;

        while let Some(mut seq) = queue.pop_front() {
            match seq {
                SequenceRow::Constraint(ref mut constraint) => {
                    let mut lhs_list_vars = vec![];
                    let mut rhs_list_vars = vec![];
                    constraint.lhs.extract_vars(&mut lhs_list_vars);
                    constraint.rhs.extract_vars(&mut rhs_list_vars);

                    let unknown_vars: Vec<_> = lhs_list_vars
                        .iter()
                        .chain(rhs_list_vars.iter())
                        .filter(|&item| !evaluated.contains(item))
                        .collect();

                    if unknown_vars.len() == 0 {
                        let lhs = constraint.lhs.evaluate(&self.vars, &self.modulus).unwrap();
                        let rhs = constraint.rhs.evaluate(&self.vars, &self.modulus).unwrap();

                        assert_eq!(
                            lhs,
                            rhs,
                            "{} != {}",
                            constraint.lhs.to_expression(),
                            constraint.rhs.to_expression()
                        );
                    } else if unknown_vars.len() == 1 {
                        let mut _new_eq = Node::empty();

                        if lhs_list_vars.contains(unknown_vars[0]) {
                            _new_eq = constraint.lhs
                                .isolate_term(unknown_vars[0], &constraint.rhs)
                                .unwrap();
                        } else {
                            _new_eq = constraint.rhs
                                .isolate_term(unknown_vars[0], &constraint.lhs)
                                .unwrap();
                        }

                        let result = _new_eq.evaluate(&self.vars, &self.modulus);
                        match result {
                            Ok(value) => {
                                self.vars
                                    .entry(unknown_vars[0].to_string())
                                    .and_modify(|v| {
                                        *v = value.clone();
                                    })
                                    .or_insert(value);

                                evaluated.insert(unknown_vars[0].to_string());
                            }
                            Err(_) => {}
                        }

                        queue.push_back(seq);
                    } else {
                        queue.push_back(seq);
                    }
                }

                SequenceRow::Assignment(ref name, ref mut node) => {
                    let mut list_vars = vec![];
                    node.extract_vars(&mut list_vars);

                    let is_subset = list_vars.iter().all(|item| evaluated.contains(item));

                    if is_subset {
                        let result = node.evaluate(&self.vars, &self.modulus).unwrap();
                        self.vars
                            .entry(name.to_string())
                            .and_modify(|v| {
                                *v = result.clone();
                            })
                            .or_insert(result);

                        evaluated.insert(name.to_string());
                    } else {
                        queue.push_back(seq);
                    }
                }

                SequenceRow::Hint(ref name, ref func, ref args) => {
                    let is_subset = args.iter().all(|item| evaluated.contains(item));

                    if is_subset {
                        let scope = PyDict::new(py);

                        for arg in args {
                            let value = self.vars
                                .get(arg)
                                .expect(&format!("Argument not exist: {}", arg));
                            scope.set_item(arg.to_string(), value)?;
                        }

                        let result = func.call(py, (), Some(scope))?;

                        if let Ok(py_int) = result.downcast::<PyInt>(py) {
                            let final_int = BigUint::parse_bytes(
                                py_int.to_string().as_bytes(),
                                10
                            ).expect("Non deterministic result must be Integer");

                            self.vars.entry(name.to_string()).and_modify(|v| {
                                *v = final_int;
                            });
                            evaluated.insert(name.to_string());
                        } else {
                            return Err(
                                PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                                    "Non deterministic result must be Integer"
                                )
                            );
                        }
                    } else {
                        queue.push_back(seq);
                    }
                }
            }

            current_loop += 1;
            if current_loop > max_loop {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Evaluation timeout: unique solution might not exist for the given constraints"
                );
            }
        }

        Ok(())
    }

    pub fn solve(
        &mut self,
        py: Python,
        inputs: HashMap<String, BigUint>
    ) -> PyResult<HashMap<String, BigUint>> {
        match self.evaluate(py, inputs) {
            Ok(_) => { Ok(self.vars.clone()) }
            Err(e) => Err(e),
        }
    }

    pub fn get_witness_vector(&self) -> Vec<String> {
        get_witness_vector(&self.vars, &self.inputs, &self.outputs, &self.public_vars)
    }

    pub fn compile_to_r1cs(
        &mut self
    ) -> PyResult<
        Vec<
            (
                Vec<(usize, usize, BigUint)>,
                Vec<(usize, usize, BigUint)>,
                Vec<(usize, usize, BigUint)>,
            )
        >
    > {
        Ok(compile(self))
    }

    pub fn compile_to_plonkish(
        &mut self
    ) -> PyResult<(Vec<(BigUint, BigUint, BigUint, BigUint, BigUint, [String; 3])>, Vec<usize>)> {
        Ok(plonkish::compile(self))
    }
}
