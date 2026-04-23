#!/usr/bin/env python3
"""Cross-check script: computes hash_to_curve_G2 for a given message using py_ecc,
outputs the 256-byte EIP-2537 encoded G2 point as hex.

Usage: python3 script/bls_htc.py <message_string>

Uses the POP ciphersuite DST (BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_)
matching the Solidity BLS12381 library.
"""

import hashlib
import sys
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.fields.field_elements import FQ2
from py_ecc.optimized_bls12_381 import normalize


DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"


def fp_to_64(x: int) -> bytes:
    """Encode a field element as 64 bytes (big-endian, zero-padded)."""
    return x.to_bytes(64, "big")


def g2_to_eip2537(point) -> bytes:
    """Convert a py_ecc G2 point to 256-byte EIP-2537 encoding.

    EIP-2537 Fp2 encoding: c0 (real, 64 bytes) || c1 (imaginary, 64 bytes)
    Full G2 point: x_c0 || x_c1 || y_c0 || y_c1
    """
    norm = normalize(point)
    x: FQ2 = norm[0]
    y: FQ2 = norm[1]
    # coeffs[0] = real (c0), coeffs[1] = imaginary (c1)
    return (
        fp_to_64(x.coeffs[0])
        + fp_to_64(x.coeffs[1])
        + fp_to_64(y.coeffs[0])
        + fp_to_64(y.coeffs[1])
    )


def main():
    message = sys.argv[1].encode("utf-8")
    point = hash_to_G2(message, DST, hashlib.sha256)
    encoded = g2_to_eip2537(point)
    # Output as 0x-prefixed hex for Foundry FFI
    sys.stdout.write("0x" + encoded.hex())


if __name__ == "__main__":
    main()
