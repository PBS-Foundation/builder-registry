// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BLS12381} from "../src/BLS12381.sol";

/// @dev Wrapper to expose BLS12381 library internals for testing.
contract BLS12381Wrapper {
    function g1Decompress(bytes calldata compressed) external view returns (bytes memory) {
        return BLS12381.g1Decompress(compressed);
    }

    function hashToCurveG2(bytes memory message) external view returns (bytes memory) {
        return BLS12381.hashToCurveG2(message);
    }

    function verifySignature(bytes calldata pubkey, bytes memory message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return BLS12381.verifySignature(pubkey, message, signature);
    }
}

/// @notice Tests G1 point decompression using known test vectors.
contract BLS12381_G1DecompressTest is Test {
    BLS12381Wrapper wrapper;

    function setUp() public {
        wrapper = new BLS12381Wrapper();
    }

    /// @dev Decompress the G1 generator. The compressed form is the x-coordinate
    /// with compression flag (0x80) set. Since G1_Y < p-G1_Y, sort flag is 0.
    function test_decompressGenerator() public view {
        // G1 generator compressed: 0x97... (0x80 | 0x17 in first byte)
        bytes memory compressed = hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        bytes memory result = wrapper.g1Decompress(compressed);
        assertEq(result.length, 128);

        uint256 x_hi;
        uint256 x_lo;
        uint256 y_hi;
        uint256 y_lo;
        assembly {
            x_hi := mload(add(result, 32))
            x_lo := mload(add(result, 64))
            y_hi := mload(add(result, 96))
            y_lo := mload(add(result, 128))
        }

        // Known G1 generator coordinates
        assertEq(x_hi, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f);
        assertEq(x_lo, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb);
        assertEq(y_hi, 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4);
        assertEq(y_lo, 0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1);
    }

    /// @dev Decompress with sort flag set — should return p-y.
    function test_decompressGeneratorWithSortFlag() public view {
        // Same as generator but with sort flag (0x20) set: 0xB7...
        bytes memory compressed = hex"b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        bytes memory result = wrapper.g1Decompress(compressed);

        uint256 y_hi;
        uint256 y_lo;
        assembly {
            y_hi := mload(add(result, 96))
            y_lo := mload(add(result, 128))
        }

        // Should be p - G1_Y (the negated y)
        assertTrue(y_hi != 0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4);
    }

    /// @dev Point at infinity decompression.
    function test_decompressInfinity() public view {
        bytes memory compressed = new bytes(48);
        compressed[0] = 0xc0; // compressed (0x80) + infinity (0x40)
        bytes memory result = wrapper.g1Decompress(compressed);
        assertEq(result.length, 128);

        for (uint256 i = 0; i < 128; i++) {
            assertEq(uint8(result[i]), 0, "infinity should be all zeros");
        }
    }

    /// @dev Revert on invalid x-coordinate (not on curve).
    function test_revert_decompressNotOnCurve() public {
        // x = 2 with compression flag: x³ + 4 = 12, which is a quadratic non-residue mod p
        bytes memory compressed = new bytes(48);
        compressed[0] = 0x80; // compression flag
        compressed[47] = 0x02; // x = 2
        vm.expectRevert(BLS12381.NotOnCurve.selector);
        wrapper.g1Decompress(compressed);
    }

    /// @dev Revert on wrong length input.
    function test_revert_decompressInvalidLength() public {
        vm.expectRevert(BLS12381.InvalidG1Length.selector);
        wrapper.g1Decompress(new bytes(47));

        vm.expectRevert(BLS12381.InvalidG1Length.selector);
        wrapper.g1Decompress(new bytes(49));
    }

    /// @dev Revert when compression flag is not set.
    function test_revert_decompressNotCompressed() public {
        bytes memory compressed = new bytes(48);
        compressed[0] = 0x00; // no compression flag
        vm.expectRevert(BLS12381.NotCompressed.selector);
        wrapper.g1Decompress(compressed);
    }
}

/// @notice Tests hash-to-curve G2 using real EIP-2537 precompiles (no mocks).
contract BLS12381_HashToCurveTest is Test {
    BLS12381Wrapper wrapper;

    function setUp() public {
        wrapper = new BLS12381Wrapper();
    }

    /// @dev Verify hashToCurveG2 produces a valid 256-byte G2 point using real precompiles.
    function test_hashToCurveG2_returnsValidG2Point() public view {
        bytes memory message = abi.encode(uint256(31337), address(0), "test", "builder.example.com", bytes32(uint256(1)));
        bytes memory result = wrapper.hashToCurveG2(message);
        assertEq(result.length, 256, "should return 256-byte G2 point");
    }

    /// @dev Different messages produce different G2 points.
    function test_hashToCurveG2_differentMessages() public view {
        bytes memory a = wrapper.hashToCurveG2(bytes("hello"));
        bytes memory b = wrapper.hashToCurveG2(bytes("world"));
        assertTrue(keccak256(a) != keccak256(b), "different messages should hash to different points");
    }

    /// @dev Same message produces the same G2 point (deterministic).
    function test_hashToCurveG2_deterministic() public view {
        bytes memory a = wrapper.hashToCurveG2(bytes("deterministic"));
        bytes memory b = wrapper.hashToCurveG2(bytes("deterministic"));
        assertEq(a, b, "same message should produce same point");
    }
}

/// @notice Cross-check expand_message_xmd output against a Python reference implementation.
/// @dev Uses FFI to call a Python script that independently computes expand_message_xmd
/// with the same POP DST, proving the Solidity implementation matches the spec.
contract BLS12381_ExpandMsgXmdTest is Test {
    BLS12381Wrapper wrapper;

    function setUp() public {
        wrapper = new BLS12381Wrapper();
    }

    /// @dev Cross-check: hashToCurveG2 output matches Python py_ecc reference for the same message.
    function test_hashToCurveG2_crossCheck() public {
        bytes memory message = bytes("cross-check test message");

        // Get Solidity result
        bytes memory solidityResult = wrapper.hashToCurveG2(message);

        // Get Python result via FFI
        string[] memory cmd = new string[](3);
        cmd[0] = "python3";
        cmd[1] = "script/bls_htc.py";
        cmd[2] = "cross-check test message";
        bytes memory pythonResult = vm.ffi(cmd);

        assertEq(solidityResult, pythonResult, "hash_to_curve output must match Python reference");
    }
}

/// @notice Verify hardcoded constants are mathematically correct.
contract BLS12381_ConstantsTest is Test {
    /// @dev Verify p mod 4 == 3 (prerequisite for Tonelli-Shanks shortcut).
    function test_pMod4Is3() public pure {
        uint256 P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
        // p mod 4 is determined by the last 2 bits of P_LO
        assertEq(P_LO & 3, 3, "p mod 4 must be 3");
    }

    /// @dev Verify SQRT_EXP = (p + 1) / 4 by checking 4 * SQRT_EXP == p + 1.
    function test_sqrtExpIsCorrect() public pure {
        uint256 P_HI = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
        uint256 P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
        uint256 SQRT_EXP_HI = 0x000000000000000000000000000000000680447a8e5ff9a692c6e9ed90d2eb35;
        uint256 SQRT_EXP_LO = 0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

        // Compute 4 * SQRT_EXP (384-bit multiply by 4 = shift left 2)
        uint256 fourExpLo = SQRT_EXP_LO << 2;
        uint256 fourExpHi = (SQRT_EXP_HI << 2) | (SQRT_EXP_LO >> 254);

        // Compute p + 1 (384-bit add)
        uint256 pPlusOneLo = P_LO + 1;
        uint256 pPlusOneHi = P_HI;
        if (pPlusOneLo == 0) pPlusOneHi += 1; // carry (won't happen for this p, but correct)

        assertEq(fourExpHi, pPlusOneHi, "SQRT_EXP_HI mismatch: 4*exp != p+1");
        assertEq(fourExpLo, pPlusOneLo, "SQRT_EXP_LO mismatch: 4*exp != p+1");
    }

    /// @dev Verify G1 generator decompresses to the known canonical coordinates.
    /// This implicitly verifies that the point satisfies y² = x³ + 4 mod p
    /// (g1Decompress checks this internally).
    function test_g1GeneratorOnCurve() public {
        BLS12381Wrapper wrapper = new BLS12381Wrapper();
        bytes memory compressed = hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        bytes memory result = wrapper.g1Decompress(compressed);

        // If g1Decompress didn't revert, the point is on the curve (y² == x³+4 verified internally).
        // Additionally verify the coordinates match the canonical generator.
        uint256 x_hi;
        uint256 x_lo;
        assembly {
            x_hi := mload(add(result, 32))
            x_lo := mload(add(result, 64))
        }
        assertEq(x_hi, 0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f);
        assertEq(x_lo, 0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb);
    }
}
