#!/usr/bin/env python3
"""Generate a real BLS12-381 signature for OpenBuilderRegistry tests.

Usage: bls_sign.py <chainid> <registry_address> <fqdn> <nonce_hex>

Outputs a single 0x-prefixed hex string (for Foundry vm.ffi):
  48-byte compressed G1 pubkey || 256-byte uncompressed G2 signature = 304 bytes

Uses a deterministic test private key derived from a fixed IKM.
"""
import sys
import eth_abi
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import signature_to_G2
from py_ecc.optimized_bls12_381 import normalize

# Deterministic test key (DO NOT use in production)
TEST_IKM = b"builder-registry-test-key-material-00"
SK = bls.KeyGen(TEST_IKM)
PK = bls.SkToPk(SK)  # 48 bytes, compressed G1


def g2_to_uncompressed(sig_compressed: bytes) -> bytes:
    """Convert 96-byte compressed G2 to 256-byte EIP-2537 uncompressed format."""
    pt = normalize(signature_to_G2(sig_compressed))
    x, y = pt[0], pt[1]
    # EIP-2537 Fp2 layout: c0 (real, 64 bytes) || c1 (imaginary, 64 bytes)
    # G2 point: x_c0 || x_c1 || y_c0 || y_c1
    def fp_to_64(val):
        return int(val).to_bytes(64, "big")
    return fp_to_64(x.coeffs[0]) + fp_to_64(x.coeffs[1]) + fp_to_64(y.coeffs[0]) + fp_to_64(y.coeffs[1])


def main():
    chainid = int(sys.argv[1])
    registry = sys.argv[2]  # hex address with 0x
    fqdn = sys.argv[3]
    nonce = bytes.fromhex(sys.argv[4].replace("0x", ""))

    # Encode message exactly as Solidity: abi.encode(uint256, address, bytes, string, bytes32)
    message = eth_abi.encode(
        ["uint256", "address", "bytes", "string", "bytes32"],
        [chainid, registry, PK, fqdn, nonce],
    )

    sig_compressed = bls.Sign(SK, message)
    sig_uncompressed = g2_to_uncompressed(sig_compressed)

    # Output as single 0x-prefixed hex blob (Foundry vm.ffi decodes this to bytes)
    print("0x" + PK.hex() + sig_uncompressed.hex())


if __name__ == "__main__":
    main()
