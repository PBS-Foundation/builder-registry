// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BLS12381
/// @notice Minimal BLS12-381 signature verification library using EIP-2537 precompiles.
/// @dev Supports compressed G1 pubkeys (48 bytes) and uncompressed G2 signatures:
/// - 192 bytes: standard uncompressed (4 x 48-byte Fp, Zcash byte order c1||c0)
/// - 256 bytes: EIP-2537 native (4 x 64-byte Fp, c0||c1 order)
/// Uses MODEXP (EIP-198) for G1 point decompression and field arithmetic.
///
/// References:
/// - BLS signatures: draft-irtf-cfrg-bls-signature-05 §3.1 (CoreVerify)
/// - Hash-to-curve: RFC 9380 §5 (hash_to_curve), §5.2 (hash_to_field), §5.3.1 (expand_message_xmd)
/// - G1 compression: Zcash serialization format (https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html §appendix-C)
/// - Precompiles: EIP-2537 (BLS12-381 precompiles, Pectra)
library BLS12381 {
    /// @dev Compressed G1 point is not exactly 48 bytes.
    error InvalidG1Length();
    /// @dev Input does not have the compression flag (0x80) set.
    error NotCompressed();
    /// @dev The x-coordinate does not correspond to a point on BLS12-381 G1 (y² ≠ x³ + 4).
    error NotOnCurve();
    /// @dev MODEXP precompile call failed.
    error ModexpFailed();
    /// @dev MAP_FP2_TO_G2 precompile call failed.
    error MapFp2ToG2Failed();
    /// @dev G2ADD precompile call failed.
    error G2AddFailed();
    /// @dev G2 signature is not 192 or 256 bytes.
    error InvalidG2Length();
    /// @dev expand_message_xmd output length exceeds 255 blocks.
    error EllTooLarge();

    /// @dev EIP-2537 precompile addresses (Pectra):
    /// 0x0b G1ADD, 0x0c G1MSM, 0x0d G2ADD, 0x0e G2MSM,
    /// 0x0f PAIRING, 0x10 MAP_FP_TO_G1, 0x11 MAP_FP2_TO_G2
    address private constant G2ADD = address(0x0d);
    address private constant PAIRING = address(0x0f);
    address private constant MAP_FP2_TO_G2 = address(0x11);

    /// @dev BLS12-381 field modulus p, stored as two 256-bit words (hi, lo).
    /// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 private constant P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    /// @dev (p+1)/4, the exponent for modular square root when p ≡ 3 (mod 4).
    uint256 private constant SQRT_EXP_HI = 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 private constant SQRT_EXP_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

    /// @dev Canonical BLS12-381 G1 generator point (uncompressed, 128 bytes).
    /// Source: https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-11.html §4.2.1
    uint256 private constant G1_X_HI = 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant G1_X_LO = 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint256 private constant G1_Y_HI = 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4;
    uint256 private constant G1_Y_LO = 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;

    /// @dev Domain separation tag for the POP ciphersuite.
    /// Matches Ethereum CL: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
    bytes private constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// @notice Verifies a BLS12-381 signature over a message.
    /// @dev Implements CoreVerify from draft-irtf-cfrg-bls-signature-05 §3.1:
    /// check e(-pk, H(m)) · e(G1, sig) == 1 via the EIP-2537 PAIRING precompile.
    /// @param compressedPubkey 48-byte compressed G1 public key
    /// @param message The signed message bytes
    /// @param signature Uncompressed G2 signature: 192 bytes (Zcash) or 256 bytes (EIP-2537)
    /// @return True if the signature is valid
    function verifySignature(bytes calldata compressedPubkey, bytes memory message, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        bytes memory pk = g1Decompress(compressedPubkey);
        bytes memory sig = _normalizeG2(signature);
        bytes memory msgHash = hashToCurveG2(message);

        // EIP-2537 pairing input layout (768 bytes):
        // [0x000:0x080]  G1 point 1: -pk (128 bytes, negated y)
        // [0x080:0x180]  G2 point 1: H(m) (256 bytes)
        // [0x180:0x200]  G1 point 2: G1 generator (128 bytes)
        // [0x200:0x300]  G2 point 2: sig (256 bytes)
        bytes memory pairingInput = new bytes(768);
        assembly {
            let dst := add(pairingInput, 32)

            // Pair 1: negated pubkey (negate y: p - y)
            let src := add(pk, 32)
            // Copy x unchanged
            mcopy(dst, src, 64)
            // Negate y: 384-bit subtraction p - y with borrow
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

            // Pair 2: normalized signature from memory (256 bytes)
            mcopy(dst, add(sig, 32), 256)
        }

        (bool ok, bytes memory result) = PAIRING.staticcall(pairingInput);
        if (!ok || result.length != 32) return false;
        return abi.decode(result, (uint256)) == 1;
    }

    /// @notice Decompresses a 48-byte compressed G1 point to 128-byte uncompressed form.
    /// @dev Implements Zcash compressed G1 deserialization:
    /// - Bit 7 of byte 0: compression flag (must be 1)
    /// - Bit 6 of byte 0: point-at-infinity flag
    /// - Bit 5 of byte 0: sort flag (selects the lexicographically larger y)
    /// - Remaining bits: big-endian x-coordinate
    /// Computes y = sqrt(x³ + 4) mod p using Tonelli-Shanks shortcut (p ≡ 3 mod 4).
    /// @param compressed 48-byte compressed G1 point (with flag byte).
    /// @return 128-byte uncompressed G1 point in EIP-2537 format.
    function g1Decompress(bytes calldata compressed) internal view returns (bytes memory) {
        if (compressed.length != 48) revert InvalidG1Length();

        uint256 x_hi;
        uint256 x_lo;
        uint256 flagByte;

        assembly {
            let word1 := calldataload(compressed.offset)
            flagByte := shr(248, word1)
            // Mask out top 3 flag bits to get x_hi (keep lower 125 bits of first 128)
            x_hi := and(shr(128, word1), 0x1fffffffffffffffffffffffffffffff)
            x_lo := calldataload(add(compressed.offset, 16))
        }

        if (flagByte & 0x80 == 0) revert NotCompressed();

        // Point at infinity
        if (flagByte & 0x40 != 0) {
            return new bytes(128);
        }

        bool wantLargest = (flagByte & 0x20) != 0;

        // Step 1: Compute x³ mod p via MODEXP precompile (address 0x05)
        uint256 rhs_hi;
        uint256 rhs_lo;
        {
            bytes memory buf = new bytes(225);
            bool ok;
            // MODEXP input layout (225 bytes):
            // [0x00:0x20]  base_len  = 64
            // [0x20:0x40]  exp_len   = 1
            // [0x40:0x60]  mod_len   = 64
            // [0x60:0xa0]  base      = x (64 bytes: x_hi || x_lo)
            // [0xa0:0xa1]  exp       = 3
            // [0xa1:0xe1]  mod       = p (64 bytes: P_HI || P_LO)
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
            if (!ok) revert ModexpFailed();
        }

        // Step 2: rhs = x³ + 4 (BLS12-381 G1 curve equation: y² = x³ + 4)
        unchecked {
            rhs_lo += 4;
        }
        if (rhs_lo < 4) rhs_hi += 1;

        // Step 3: y = rhs^((p+1)/4) mod p (Tonelli-Shanks shortcut for p ≡ 3 mod 4)
        uint256 y_hi;
        uint256 y_lo;
        {
            bytes memory buf = new bytes(288);
            bool ok;
            // MODEXP input layout (288 bytes):
            // [0x00:0x20]    base_len  = 64
            // [0x20:0x40]    exp_len   = 64
            // [0x40:0x60]    mod_len   = 64
            // [0x60:0xa0]    base      = rhs (64 bytes: rhs_hi || rhs_lo)
            // [0xa0:0xe0]    exp       = (p+1)/4 (64 bytes: SQRT_EXP_HI || SQRT_EXP_LO)
            // [0xe0:0x120]   mod       = p (64 bytes: P_HI || P_LO)
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
            if (!ok) revert ModexpFailed();
        }

        // Step 4: Verify y² ≡ rhs (mod p) — rejects x-coordinates not on the curve
        {
            bytes memory buf = new bytes(225);
            bool ok;
            uint256 ysq_hi;
            uint256 ysq_lo;
            // MODEXP input layout (225 bytes): same as step 1, but base=y, exp=2
            assembly {
                let p := add(buf, 32)
                mstore(p, 64)
                mstore(add(p, 0x20), 1)
                mstore(add(p, 0x40), 64)
                mstore(add(p, 0x60), y_hi)
                mstore(add(p, 0x80), y_lo)
                mstore8(add(p, 0xa0), 2)
                mstore(add(p, 0xa1), P_HI)
                mstore(add(p, 0xc1), P_LO)
                ok := staticcall(gas(), 5, p, 225, p, 64)
                ysq_hi := mload(p)
                ysq_lo := mload(add(p, 0x20))
            }
            if (!ok) revert ModexpFailed();
            if (ysq_hi != rhs_hi || ysq_lo != rhs_lo) revert NotOnCurve();
        }

        // Step 5: Select correct y — choose between y and p-y based on sort flag
        // 384-bit subtraction: alt_y = p - y with borrow detection
        uint256 alt_y_lo;
        uint256 alt_y_hi;
        unchecked {
            alt_y_lo = P_LO - y_lo;
        }
        alt_y_hi = (alt_y_lo > P_LO) ? P_HI - y_hi - 1 : P_HI - y_hi;

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

    /// @notice Hashes a message to a G2 point per RFC 9380 §5 (hash_to_curve).
    /// @dev Pipeline: expand_message_xmd (§5.3.1) → hash_to_field (§5.2) → map_to_curve (EIP-2537) → G2ADD.
    /// @param message The message bytes to hash.
    /// @return 256-byte G2 point in EIP-2537 format.
    function hashToCurveG2(bytes memory message) internal view returns (bytes memory) {
        bytes memory uniform = _expandMsgXmd(message, 256);

        // hash_to_field (RFC 9380 §5.2): reduce 4 × 64-byte blocks mod p → 2 Fp2 elements
        bytes memory u0 = _reduceToFp2(uniform, 0);
        bytes memory u1 = _reduceToFp2(uniform, 128);

        // map_to_curve (RFC 9380 §6): MAP_FP2_TO_G2 precompile for each Fp2 element
        (bool ok0, bytes memory q0) = MAP_FP2_TO_G2.staticcall(u0);
        if (!ok0 || q0.length != 256) revert MapFp2ToG2Failed();

        (bool ok1, bytes memory q1) = MAP_FP2_TO_G2.staticcall(u1);
        if (!ok1 || q1.length != 256) revert MapFp2ToG2Failed();

        // G2ADD(Q0, Q1) — place q1 data adjacent to q0 data to avoid allocation
        bool ok2;
        bytes memory result;
        assembly {
            // q0 layout: [length(32)] [data(256)]
            // Write q1's 256 data bytes right after q0's data
            mcopy(add(add(q0, 32), 256), add(q1, 32), 256)
            // staticcall G2ADD with 512 bytes starting at q0's data
            ok2 := staticcall(gas(), 0x0d, add(q0, 32), 512, 0, 0)
            // Validate precompile returned exactly 256 bytes
            if iszero(eq(returndatasize(), 256)) { ok2 := 0 }
            // Copy result
            result := mload(0x40)
            mstore(result, 256)
            returndatacopy(add(result, 32), 0, returndatasize())
            mstore(0x40, add(result, 288))
        }
        if (!ok2) revert G2AddFailed();

        return result;
    }

    /// @dev Reduces two consecutive 64-byte blocks at `offset` in `data` mod p,
    /// forming a 128-byte Fp2 element in EIP-2537 order (c0 || c1).
    /// Per RFC 9380 §5.2, the first 64 bytes map to c0 (real) and the next to c1 (imaginary).
    function _reduceToFp2(bytes memory data, uint256 offset) private view returns (bytes memory) {
        bytes memory result = new bytes(128);
        _fpReduceBlock(data, offset, result, 0);
        _fpReduceBlock(data, offset + 64, result, 64);
        return result;
    }

    /// @dev Reduces a 64-byte block from `src[srcOff..srcOff+64]` mod p via MODEXP,
    /// writes the 64-byte result to `dst[dstOff..dstOff+64]`.
    function _fpReduceBlock(bytes memory src, uint256 srcOff, bytes memory dst, uint256 dstOff) private view {
        // MODEXP input layout (225 bytes): same structure as g1Decompress step 1,
        // but base = src[srcOff:srcOff+64] and exp = 1 (identity reduction).
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

    /// @dev Normalizes a G2 signature to 256-byte EIP-2537 format.
    /// - 256 bytes: already EIP-2537, copy as-is (c0||c1 per Fp2, 64-byte padded)
    /// - 192 bytes: Zcash uncompressed (c1||c0 per Fp2, 48-byte), reorder + zero-pad
    ///
    /// Zcash 192-byte layout:  x_c1(48) || x_c0(48) || y_c1(48) || y_c0(48)
    /// EIP-2537 256-byte layout: x_c0(64) || x_c1(64) || y_c0(64) || y_c1(64)
    function _normalizeG2(bytes calldata sig) private pure returns (bytes memory out) {
        out = new bytes(256);
        if (sig.length == 256) {
            assembly {
                calldatacopy(add(out, 32), sig.offset, 256)
            }
            return out;
        }
        if (sig.length != 192) revert InvalidG2Length();
        assembly {
            let dst := add(out, 32)
            // x_c0: 16 zero pad + sig[48:96]
            calldatacopy(add(dst, 16), add(sig.offset, 48), 48)
            // x_c1: 16 zero pad + sig[0:48]
            calldatacopy(add(dst, 80), sig.offset, 48)
            // y_c0: 16 zero pad + sig[144:192]
            calldatacopy(add(dst, 144), add(sig.offset, 144), 48)
            // y_c1: 16 zero pad + sig[96:144]
            calldatacopy(add(dst, 208), add(sig.offset, 96), 48)
        }
        return out;
    }

    /// @dev Implements expand_message_xmd per RFC 9380 §5.3.1 with SHA-256 and the POP DST.
    /// Produces `lenInBytes` pseudorandom bytes from a message using the XMD construction.
    function _expandMsgXmd(bytes memory message, uint256 lenInBytes) private pure returns (bytes memory) {
        uint256 ell = (lenInBytes + 31) / 32;
        if (ell > 255) revert EllTooLarge();

        // DST_prime = DST || I2OSP(len(DST), 1) per RFC 9380 §5.3.1
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        // Z_pad = I2OSP(0, r_in_bytes) where r_in_bytes = 64 for SHA-256
        bytes memory zPad = new bytes(64);

        // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
        bytes32 b0 = sha256(abi.encodePacked(zPad, message, uint16(lenInBytes), uint8(0), dstPrime));
        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));

        bytes memory output = new bytes(lenInBytes);
        assembly {
            mstore(add(output, 32), bi)
        }

        // Reuse a single scratch buffer for b_i = H(b_0 XOR b_{i-1} || I2OSP(i, 1) || DST_prime)
        uint256 dstPrimeLen = dstPrime.length;
        bytes memory scratch = new bytes(33 + dstPrimeLen);
        assembly {
            let dst := add(scratch, 32)
            mcopy(add(dst, 33), add(dstPrime, 32), dstPrimeLen)
        }

        bytes32 bPrev = bi;
        for (uint256 i = 2; i <= ell; i++) {
            assembly {
                let dst := add(scratch, 32)
                mstore(dst, xor(b0, bPrev))
                mstore8(add(dst, 32), i)
            }
            bi = sha256(scratch);
            assembly {
                mstore(add(add(output, 32), mul(sub(i, 1), 32)), bi)
            }
            bPrev = bi;
        }

        return output;
    }
}
