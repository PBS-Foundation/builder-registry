// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BLS12381
/// @notice Minimal BLS12-381 signature verification library using EIP-2537 precompiles.
/// @dev Supports compressed G1 pubkeys (48 bytes) and uncompressed G2 signatures (256 bytes).
///      Uses MODEXP (EIP-198) for G1 point decompression and field arithmetic.
library BLS12381 {
    // ── EIP-2537 precompile addresses (Pectra) ─────────────────────────────
    //   0x0b G1ADD    0x0d G2ADD       0x0f PAIRING
    //   0x0c G1MSM    0x0e G2MSM       0x10 MAP_FP_TO_G1
    //                                  0x11 MAP_FP2_TO_G2
    address private constant G2ADD = address(0x0d);
    address private constant PAIRING = address(0x0f);
    address private constant MAP_FP2_TO_G2 = address(0x11);

    // ── BLS12-381 field modulus p ───────────────────────────────────────────
    // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 private constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // (p+1)/4 — exponent for modular square root (p ≡ 3 mod 4)
    uint256 private constant SQRT_EXP_HI = 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 private constant SQRT_EXP_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

    // ── G1 generator (uncompressed) ─────────────────────────────────────────
    uint256 private constant G1_X_HI = 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant G1_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint256 private constant G1_Y_HI = 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4;
    uint256 private constant G1_Y_LO = 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

    // ── DST for POP ciphersuite ─────────────────────────────────────────────
    bytes private constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // ── Public API ──────────────────────────────────────────────────────────

    /// @notice Verifies a BLS12-381 signature over a message.
    /// @param compressedPubkey 48-byte compressed G1 public key
    /// @param message The signed message bytes
    /// @param signature 256-byte uncompressed G2 signature
    /// @return True if the signature is valid
    function verifySignature(bytes calldata compressedPubkey, bytes memory message, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        bytes memory pk = g1Decompress(compressedPubkey);
        bytes memory msgHash = hashToCurveG2(message);

        // Build pairing input: e(-pk, H(m)) · e(G1_gen, sig) == 1
        // 768 bytes = neg_pk(128) + msgHash(256) + g1Gen(128) + sig(256)
        bytes memory pairingInput = new bytes(768);
        assembly {
            let dst := add(pairingInput, 32)

            // Pair 1: negated pubkey (negate y: p - y)
            let src := add(pk, 32)
            // Copy x unchanged
            mcopy(dst, src, 64)
            // Negate y
            let yHi := mload(add(src, 0x40))
            let yLo := mload(add(src, 0x60))
            let negLo := sub(P_LO, yLo)
            let borrow := gt(negLo, P_LO)
            let negHi := sub(sub(P_HI, yHi), borrow)
            mstore(add(dst, 0x40), negHi)
            mstore(add(dst, 0x60), negLo)
            dst := add(dst, 128)

            // Pair 1: message hash (256 bytes)
            mcopy(dst, add(msgHash, 32), 256)
            dst := add(dst, 256)

            // Pair 2: G1 generator (128 bytes)
            mstore(dst, G1_X_HI)
            mstore(add(dst, 0x20), G1_X_LO)
            mstore(add(dst, 0x40), G1_Y_HI)
            mstore(add(dst, 0x60), G1_Y_LO)
            dst := add(dst, 128)

            // Pair 2: signature from calldata (256 bytes)
            calldatacopy(dst, signature.offset, 256)
        }

        (bool ok, bytes memory result) = PAIRING.staticcall(pairingInput);
        if (!ok || result.length != 32) return false;
        return abi.decode(result, (uint256)) == 1;
    }

    // ── G1 Decompression ────────────────────────────────────────────────────

    /// @notice Decompresses a 48-byte compressed G1 point to 128-byte uncompressed form.
    function g1Decompress(bytes calldata compressed) internal view returns (bytes memory) {
        require(compressed.length == 48, "invalid G1 length");

        uint256 x_hi;
        uint256 x_lo;
        uint256 flagByte;

        assembly {
            let word1 := calldataload(compressed.offset)
            flagByte := shr(248, word1)
            x_hi := and(shr(128, word1), 0x1fffffffffffffffffffffffffffffff)
            x_lo := calldataload(add(compressed.offset, 16))
        }

        require(flagByte & 0x80 != 0, "not compressed");

        // Point at infinity
        if (flagByte & 0x40 != 0) {
            return new bytes(128);
        }

        bool wantLargest = (flagByte & 0x20) != 0;

        // Compute x³ mod p via MODEXP(x, 3, p)
        uint256 rhs_hi;
        uint256 rhs_lo;
        {
            bytes memory buf = new bytes(225);
            bool ok;
            assembly {
                let p := add(buf, 32)
                mstore(p, 64)
                mstore(add(p, 0x20), 1)
                mstore(add(p, 0x40), 64)
                mstore(add(p, 0x60), x_hi)
                mstore(add(p, 0x80), x_lo)
                mstore8(add(p, 0xa0), 3)
                mstore(add(p, 0xa1), P_HI)
                mstore(add(p, 0xc1), P_LO)
                ok := staticcall(gas(), 5, p, 225, p, 64)
                rhs_hi := mload(p)
                rhs_lo := mload(add(p, 0x20))
            }
            require(ok, "modexp x^3 failed");
        }

        // rhs = x³ + 4 (BLS12-381 G1: y² = x³ + 4)
        unchecked {
            rhs_lo += 4;
        }
        if (rhs_lo < 4) rhs_hi += 1;

        // y = rhs^((p+1)/4) mod p
        uint256 y_hi;
        uint256 y_lo;
        {
            bytes memory buf = new bytes(288);
            bool ok;
            assembly {
                let p := add(buf, 32)
                mstore(p, 64)
                mstore(add(p, 0x20), 64)
                mstore(add(p, 0x40), 64)
                mstore(add(p, 0x60), rhs_hi)
                mstore(add(p, 0x80), rhs_lo)
                mstore(add(p, 0xa0), SQRT_EXP_HI)
                mstore(add(p, 0xc0), SQRT_EXP_LO)
                mstore(add(p, 0xe0), P_HI)
                mstore(add(p, 0x100), P_LO)
                ok := staticcall(gas(), 5, p, 288, p, 64)
                y_hi := mload(p)
                y_lo := mload(add(p, 0x20))
            }
            require(ok, "modexp sqrt failed");
        }

        // alt_y = p - y
        uint256 alt_y_lo;
        uint256 alt_y_hi;
        unchecked {
            alt_y_lo = P_LO - y_lo;
        }
        alt_y_hi = (alt_y_lo > P_LO) ? P_HI - y_hi - 1 : P_HI - y_hi;

        // Select y based on sort flag
        bool yIsLargest = (y_hi > alt_y_hi) || (y_hi == alt_y_hi && y_lo > alt_y_lo);
        if (wantLargest != yIsLargest) {
            y_hi = alt_y_hi;
            y_lo = alt_y_lo;
        }

        bytes memory result = new bytes(128);
        assembly {
            let p := add(result, 32)
            mstore(p, x_hi)
            mstore(add(p, 0x20), x_lo)
            mstore(add(p, 0x40), y_hi)
            mstore(add(p, 0x60), y_lo)
        }
        return result;
    }

    // ── Hash to Curve G2 ────────────────────────────────────────────────────

    /// @notice Hashes a message to a G2 point per RFC 9380 §5.
    function hashToCurveG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory uniform = _expandMsgXmd(message, 256);

        // Reduce 4 blocks of 64 bytes mod p → form 2 Fp2 elements
        bytes memory u0 = _reduceToFp2(uniform, 0);
        bytes memory u1 = _reduceToFp2(uniform, 128);

        // MAP_FP2_TO_G2 for each Fp2 element
        (bool ok0, bytes memory q0) = MAP_FP2_TO_G2.staticcall(u0);
        require(ok0 && q0.length == 256, "map_fp2_to_g2 u0 failed");

        (bool ok1, bytes memory q1) = MAP_FP2_TO_G2.staticcall(u1);
        require(ok1 && q1.length == 256, "map_fp2_to_g2 u1 failed");

        // G2ADD(Q0, Q1)
        (bool ok2, bytes memory result) = G2ADD.staticcall(abi.encodePacked(q0, q1));
        require(ok2 && result.length == 256, "g2add failed");

        return result;
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// @dev Reduces two consecutive 64-byte blocks at `offset` in `data` mod p,
    ///      forming a 128-byte Fp2 element (c0 || c1).
    function _reduceToFp2(bytes memory data, uint256 offset) private view returns (bytes memory) {
        bytes memory result = new bytes(128);
        _fpReduceBlock(data, offset, result, 0);
        _fpReduceBlock(data, offset + 64, result, 64);
        return result;
    }

    /// @dev Reduces a 64-byte block from `src[srcOff..srcOff+64]` mod p via MODEXP,
    ///      writes the 64-byte result to `dst[dstOff..dstOff+64]`.
    function _fpReduceBlock(bytes memory src, uint256 srcOff, bytes memory dst, uint256 dstOff) private view {
        assembly {
            let scratch := mload(0x40)
            mstore(scratch, 64) // base_len
            mstore(add(scratch, 0x20), 1) // exp_len
            mstore(add(scratch, 0x40), 64) // mod_len
            mcopy(add(scratch, 0x60), add(add(src, 32), srcOff), 64) // base
            mstore8(add(scratch, 0xa0), 1) // exp = 1
            mstore(add(scratch, 0xa1), P_HI) // mod
            mstore(add(scratch, 0xc1), P_LO)

            let ok := staticcall(gas(), 5, scratch, 225, add(add(dst, 32), dstOff), 64)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev expand_message_xmd per RFC 9380 §5.3.1 with SHA-256 and the POP DST.
    function _expandMsgXmd(bytes memory message, uint256 lenInBytes) private pure returns (bytes memory) {
        uint256 ell = (lenInBytes + 31) / 32;
        require(ell <= 255, "ell too large");

        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        bytes memory zPad = new bytes(64);

        bytes32 b0 = sha256(abi.encodePacked(zPad, message, uint16(lenInBytes), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));

        bytes memory output = new bytes(lenInBytes);
        assembly {
            mstore(add(output, 32), bi)
        }

        bytes32 bPrev = bi;
        for (uint256 i = 2; i <= ell; i++) {
            bi = sha256(abi.encodePacked(b0 ^ bPrev, uint8(i), dstPrime));
            assembly {
                mstore(add(add(output, 32), mul(sub(i, 1), 32)), bi)
            }
            bPrev = bi;
        }

        return output;
    }
}
