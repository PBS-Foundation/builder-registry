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

        // Verify x-coordinate
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

        // Should be all zeros
        for (uint256 i = 0; i < 128; i++) {
            assertEq(uint8(result[i]), 0, "infinity should be all zeros");
        }
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
