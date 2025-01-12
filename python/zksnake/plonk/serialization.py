
from zksnake.polynomial import PolynomialRing
from ..utils import split_list
from ..ecc import CurvePointSize, EllipticCurve

class Proof:

    def __init__(
            self,
            tau_a,
            tau_b,
            tau_c,
            tau_z,
            tau_t_lo,
            tau_t_mid,
            tau_t_hi,
            tau_W_zeta,
            tau_W_zeta_omega,
            zeta_a,
            zeta_b,
            zeta_c,
            zeta_sigma1,
            zeta_sigma2,
            zeta_omega
        ):
        self.tau_a = tau_a
        self.tau_b = tau_b
        self.tau_c = tau_c
        self.tau_z = tau_z
        self.tau_t_lo = tau_t_lo
        self.tau_t_mid = tau_t_mid
        self.tau_t_hi = tau_t_hi
        self.tau_W_zeta = tau_W_zeta
        self.tau_W_zeta_omega = tau_W_zeta_omega
        self.zeta_a = zeta_a
        self.zeta_b = zeta_b
        self.zeta_c = zeta_c
        self.zeta_sigma1 = zeta_sigma1
        self.zeta_sigma2 = zeta_sigma2
        self.zeta_omega = zeta_omega

    @classmethod
    def from_hex(cls, s: str, crv="BN254"):
        """Parse Proof from hexstring"""

        E = EllipticCurve(crv)

        n = CurvePointSize[crv].value
        total_points = n * 9
        total_scalars = 32*2 * 6
        assert (
            len(s) == total_points + total_scalars
        ), f"Length of the Proof must equal {total_points + total_scalars} hex bytes"

        ax = s[:n]
        bx = s[n : n * 2]
        cx = s[n * 2 : n * 3]
        zx = s[n * 3 : n * 4]
        tlox = s[n * 4 : n * 5]
        tmix = s[n * 5 : n * 6]
        thix = s[n * 6 : n * 7]
        wzx = s[n * 7 : n * 8]
        wzox = s[n * 8 : n * 9]

        scalars = split_list(bytes.fromhex(s[n*9:]), 32)

        tau_a = E.from_hex(ax)
        tau_b = E.from_hex(bx)
        tau_c = E.from_hex(cx)
        tau_z = E.from_hex(zx)
        tau_t_lo = E.from_hex(tlox)
        tau_t_mid = E.from_hex(tmix)
        tau_t_hi = E.from_hex(thix)
        tau_w_zeta = E.from_hex(wzx)
        tau_w_zeta_omega = E.from_hex(wzox)

        zeta_a = int.from_bytes(scalars[0], 'little')
        zeta_b = int.from_bytes(scalars[1], 'little')
        zeta_c = int.from_bytes(scalars[2], 'little')
        zeta_sigma1 = int.from_bytes(scalars[3], 'little')
        zeta_sigma2 = int.from_bytes(scalars[4], 'little')
        zeta_omega = int.from_bytes(scalars[5], 'little')

        return Proof(
            tau_a, tau_b, tau_c, tau_z,
            tau_t_lo, tau_t_mid, tau_t_hi,
            tau_w_zeta, tau_w_zeta_omega,
            zeta_a, zeta_b, zeta_c, zeta_sigma1, zeta_sigma2, zeta_omega
        )

    def to_hex(self) -> str:
        """Return hex representation of the Proof"""
        points_hex = (
            self.tau_a.to_hex() +
            self.tau_b.to_hex() +
            self.tau_c.to_hex() +
            self.tau_z.to_hex() +
            self.tau_t_lo.to_hex() +
            self.tau_t_mid.to_hex() +
            self.tau_t_hi.to_hex() +
            self.tau_W_zeta.to_hex() +
            self.tau_W_zeta_omega.to_hex()
        )

        scalar_hex = (
            self.zeta_a.to_bytes(32, 'little') +
            self.zeta_b.to_bytes(32, 'little') +
            self.zeta_c.to_bytes(32, 'little') +
            self.zeta_sigma1.to_bytes(32, 'little') +
            self.zeta_sigma2.to_bytes(32, 'little') +
            self.zeta_omega.to_bytes(32, 'little')
        ).hex()

        return points_hex + scalar_hex
    
class ProvingKey:
    def __init__(
        self,
        n,
        tau_G1,
        selector_poly,
        selector_eval,
        permutation_poly,
        identity_poly,
        tau_selector,
        tau_permutation,
        lagrange_evals,
        curve: str = "BN254"
    ):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.n = n
        self.tau_g1 = tau_G1
        self.selector_poly = selector_poly
        self.selector_eval = selector_eval
        self.permutation_poly = permutation_poly
        self.identity_poly = identity_poly

        self.tau_selector_poly = tau_selector
        self.tau_permutation_poly = tau_permutation

        self.lagrange_evals = lagrange_evals

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):
        """Construct ProvingKey from bytes"""
        E = EllipticCurve(crv)
        n = CurvePointSize[crv].value // 2

        tau_g1 = []
        length = int.from_bytes(s[:8], 'little')
        points = split_list(s[8:8+length*n], n)
        for point in points:
            tau_g1.append(E.from_hex(point.hex()))

        s = s[8+length*n:]

        tau_selector_poly = {}
        selector_polys = []
        tau_permutation_poly = []
        for _ in range(5):
            point = s[:n]
            s = s[n:]
            selector_polys.append(E.from_hex(point.hex()))

        tau_selector_poly = {
            'L': selector_polys[0],
            'R': selector_polys[1],
            'O': selector_polys[2],
            'M': selector_polys[3],
            'C': selector_polys[4],
        }

        for _ in range(3):
            point = s[:n]
            s = s[n:]
            tau_permutation_poly.append(E.from_hex(point.hex()))

        contents = []
        n = 32
        while len(s) > 0:
            length = int.from_bytes(s[:8], 'little')
            raw_bytes = split_list(s[8:8+length*n], n)
            contents.append([])
            for b in raw_bytes:
                scalars = int.from_bytes(b, 'little')
                contents[-1].append(scalars)

            s = s[8+length*n:]

        assert len(contents) == 17, "Malformed ProvingKey structure"

        domain = len(contents[0])

        selector_poly = {
            'L': PolynomialRing(contents[0], E.order),
            'R': PolynomialRing(contents[1], E.order),
            'O': PolynomialRing(contents[2], E.order),
            'M': PolynomialRing(contents[3], E.order),
            'C': PolynomialRing(contents[4], E.order),
        }

        permutation_poly = [
            PolynomialRing(contents[5], E.order),
            PolynomialRing(contents[6], E.order),
            PolynomialRing(contents[7], E.order),
        ]

        identity_poly = [
            PolynomialRing(contents[8], E.order),
            PolynomialRing(contents[9], E.order),
            PolynomialRing(contents[10], E.order),
        ]

        selector_evals = {
            'L': contents[11],
            'R': contents[12],
            'O': contents[13],
            'M': contents[14],
            'C': contents[15],
        }

        lagrange_evals = contents[16]

        return ProvingKey(
            domain, tau_g1, selector_poly, selector_evals,
            permutation_poly, identity_poly,
            tau_selector_poly, tau_permutation_poly,
            lagrange_evals, crv
        )

    def to_bytes(self) -> bytes:
        """Return bytes representation of the ProvingKey"""
        s = b''
        int_bytesize = 32

        s += int.to_bytes(len(self.tau_g1), 8, "little")
        for t in self.tau_g1:
            s += bytes(t.to_bytes())

        for _, point in self.tau_selector_poly.items():
            s += bytes(point.to_bytes())

        for point in self.tau_permutation_poly:
            s += bytes(point.to_bytes())

        for _, poly in self.selector_poly.items():
            s += int.to_bytes(len(poly.coeffs()), 8, "little")
            for coeff in poly.coeffs():
                s += int.to_bytes(coeff, int_bytesize, 'little')

        for poly in self.permutation_poly:
            s += int.to_bytes(len(poly.coeffs()), 8, "little")
            for coeff in poly.coeffs():
                s += int.to_bytes(coeff, int_bytesize, 'little')

        for poly in self.identity_poly:
            s += int.to_bytes(len(poly.coeffs()), 8, "little")
            for coeff in poly.coeffs():
                s += int.to_bytes(coeff, int_bytesize, 'little')

        for _, evals in self.selector_eval.items():
            s += int.to_bytes(len(evals), 8, "little")
            for e in evals:
                s += int.to_bytes(e, int_bytesize, 'little')

        s += int.to_bytes(len(self.lagrange_evals), 8, "little")
        for e in self.lagrange_evals:
            s += int.to_bytes(e, int_bytesize, 'little')

        return s

class VerifyingKey:

    def __init__(
        self,
        n,
        tau_G2,
        tau_selector_poly,
        tau_permutation_poly,
        curve: str = "BN254"
    ):
        self.E = EllipticCurve(curve)
        self.order = self.E.order
        self.n = n
        self.tau_g2 = tau_G2
        self.tau_selector_poly = tau_selector_poly
        self.tau_permutation_poly = tau_permutation_poly

    @classmethod
    def from_bytes(cls, s: bytes, crv="BN254"):
        """Construct ProvingKey from bytes"""
        E = EllipticCurve(crv)
        n = CurvePointSize[crv].value // 2

        domain = int.from_bytes(s[:8], 'little')
        s = s[8:]

        tau_g2 = E.from_hex(s[:n*2].hex())
        s = s[n*2:]

        tau_selector_poly = {}
        selector_polys = []
        tau_permutation_poly = []
        for _ in range(5):
            point = s[:n]
            s = s[n:]
            selector_polys.append(E.from_hex(point.hex()))

        tau_selector_poly = {
            'L': selector_polys[0],
            'R': selector_polys[1],
            'O': selector_polys[2],
            'M': selector_polys[3],
            'C': selector_polys[4],
        }

        for _ in range(3):
            point = s[:n]
            s = s[n:]
            tau_permutation_poly.append(E.from_hex(point.hex()))

        return VerifyingKey(domain, tau_g2, tau_selector_poly, tau_permutation_poly, crv)

    def to_bytes(self) -> bytes:
        """Return bytes representation of the ProvingKey"""
        s = b''
        s += int.to_bytes(self.n, 8, 'little')
        s += bytes(self.tau_g2.to_bytes())

        for _, point in self.tau_selector_poly.items():
            s += bytes(point.to_bytes())

        for point in self.tau_permutation_poly:
            s += bytes(point.to_bytes())

        return s
