from typing import Type

# pylint: disable=no-name-in-module
from zksnake._algebra import circuit
from .r1cs import R1CS
from .plonkish import Plonkish
from .layered_circuit import LayeredCircuit

Var = circuit.Field
Field = circuit.Field
ConstraintSystem = circuit.ConstraintSystem
