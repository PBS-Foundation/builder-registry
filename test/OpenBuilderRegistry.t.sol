// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BuilderRecord, IBuilderRegistry} from "../src/interfaces/IERC8218.sol";
import {OpenBuilderRegistry} from "../src/OpenBuilderRegistry.sol";

/// @dev Harness that exposes a direct insert for unit testing the list
/// interface without needing valid BLS signatures.
contract OpenBuilderRegistryHarness is OpenBuilderRegistry {
    function directInsert(bytes calldata pubkey, string calldata fqdn) external {
        bytes32 pkHash = keccak256(pubkey);
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) {
            _builders.push(BuilderRecord({pubkey: pubkey, fqdn: fqdn}));
            _indexByPubkeyHash[pkHash] = _builders.length;
        } else {
            _builders[idx - 1].fqdn = fqdn;
        }
    }
}

/// @notice Tests input validation (pubkey length, FQDN, signature length).
contract OpenBuilderRegistry_ValidationTest is Test {
    OpenBuilderRegistry registry;

    bytes validPubkey = new bytes(48);
    bytes validSignature = new bytes(256);

    function setUp() public {
        registry = new OpenBuilderRegistry();
        validPubkey[0] = 0x80; // compression flag
    }

    function test_revert_InvalidPubkeyLength_tooShort() public {
        vm.expectRevert(abi.encodeWithSelector(OpenBuilderRegistry.InvalidPubkeyLength.selector, 47));
        registry.registerBuilder(new bytes(47), "builder.example.com", bytes32(0), validSignature);
    }

    function test_revert_InvalidPubkeyLength_tooLong() public {
        vm.expectRevert(abi.encodeWithSelector(OpenBuilderRegistry.InvalidPubkeyLength.selector, 49));
        registry.registerBuilder(new bytes(49), "builder.example.com", bytes32(0), validSignature);
    }

    function test_revert_EmptyFQDN() public {
        vm.expectRevert(OpenBuilderRegistry.EmptyFQDN.selector);
        registry.registerBuilder(validPubkey, "", bytes32(0), validSignature);
    }

    function test_revert_InvalidSignatureLength() public {
        uint256[] memory badLengths = new uint256[](6);
        badLengths[0] = 0;
        badLengths[1] = 96;
        badLengths[2] = 191;
        badLengths[3] = 193;
        badLengths[4] = 255;
        badLengths[5] = 257;

        for (uint256 i = 0; i < badLengths.length; i++) {
            vm.expectRevert(
                abi.encodeWithSelector(OpenBuilderRegistry.InvalidSignatureLength.selector, badLengths[i])
            );
            registry.registerBuilder(validPubkey, "builder.example.com", bytes32(0), new bytes(badLengths[i]));
        }
    }

    function test_accept_SignatureLength_192() public {
        // Should pass length validation (will fail at BLS verify, but not at length check)
        vm.expectRevert(OpenBuilderRegistry.SignatureVerificationFailed.selector);
        registry.registerBuilder(validPubkey, "builder.example.com", bytes32(0), new bytes(192));
    }

    function test_accept_SignatureLength_256() public {
        // Should pass length validation (will fail at BLS verify, but not at length check)
        vm.expectRevert(OpenBuilderRegistry.SignatureVerificationFailed.selector);
        registry.registerBuilder(validPubkey, "builder.example.com", bytes32(0), validSignature);
    }
}

/// @notice Tests the IBuilderList interface (uses harness to bypass BLS).
contract OpenBuilderRegistry_BuilderListTest is Test {
    OpenBuilderRegistryHarness registry;

    bytes pk1;
    bytes pk2;
    bytes pk3;

    function setUp() public {
        registry = new OpenBuilderRegistryHarness();

        pk1 = new bytes(48);
        pk1[0] = 0x01;
        pk2 = new bytes(48);
        pk2[0] = 0x02;
        pk3 = new bytes(48);
        pk3[0] = 0x03;
    }

    function test_builderCount_empty() public view {
        assertEq(registry.builderCount(0), 0);
    }

    function test_builderCount_afterInserts() public {
        registry.directInsert(pk1, "a.example.com");
        registry.directInsert(pk2, "b.example.com");
        assertEq(registry.builderCount(0), 2);
    }

    function test_builderCount_ignoresListId() public {
        registry.directInsert(pk1, "a.example.com");
        assertEq(registry.builderCount(0), 1);
        assertEq(registry.builderCount(42), 1);
        assertEq(registry.builderCount(type(uint256).max), 1);
    }

    function test_getBuilderAtIndex_returnsCorrectRecord() public {
        registry.directInsert(pk1, "a.example.com");
        registry.directInsert(pk2, "b.example.com");

        BuilderRecord memory r0 = registry.getBuilderAtIndex(0, 0);
        assertEq(r0.pubkey, pk1);
        assertEq(r0.fqdn, "a.example.com");

        BuilderRecord memory r1 = registry.getBuilderAtIndex(0, 1);
        assertEq(r1.pubkey, pk2);
        assertEq(r1.fqdn, "b.example.com");
    }

    function test_getBuilderAtIndex_ignoresListId() public {
        registry.directInsert(pk1, "a.example.com");
        BuilderRecord memory r = registry.getBuilderAtIndex(999, 0);
        assertEq(r.pubkey, pk1);
    }

    function test_revert_getBuilderAtIndex_outOfBounds() public {
        vm.expectRevert(OpenBuilderRegistry.IndexOutOfBounds.selector);
        registry.getBuilderAtIndex(0, 0);
    }

    function test_revert_getBuilderAtIndex_exactBoundary() public {
        registry.directInsert(pk1, "a.example.com");
        vm.expectRevert(OpenBuilderRegistry.IndexOutOfBounds.selector);
        registry.getBuilderAtIndex(0, 1);
    }

    function test_updateExistingBuilder_fqdnChanges() public {
        registry.directInsert(pk1, "old.example.com");
        assertEq(registry.builderCount(0), 1);

        registry.directInsert(pk1, "new.example.com");
        assertEq(registry.builderCount(0), 1);

        BuilderRecord memory r = registry.getBuilderAtIndex(0, 0);
        assertEq(r.fqdn, "new.example.com");
    }

    function test_multipleBuilders_orderPreserved() public {
        registry.directInsert(pk1, "first.example.com");
        registry.directInsert(pk2, "second.example.com");
        registry.directInsert(pk3, "third.example.com");

        assertEq(registry.builderCount(0), 3);
        assertEq(registry.getBuilderAtIndex(0, 0).fqdn, "first.example.com");
        assertEq(registry.getBuilderAtIndex(0, 1).fqdn, "second.example.com");
        assertEq(registry.getBuilderAtIndex(0, 2).fqdn, "third.example.com");
    }
}

/// @notice Full registration flow with real BLS signatures (no mocks).
/// @dev Uses FFI to call a Python script that generates real BLS12-381 signatures
/// via py_ecc. All precompiles (G1 decompression, hash-to-curve, pairing)
/// are exercised with real cryptographic inputs.
contract OpenBuilderRegistry_RegistrationTest is Test {
    OpenBuilderRegistry registry;

    string fqdn = "builder.example.com";
    bytes32 nonce = bytes32(uint256(1));

    function setUp() public {
        registry = new OpenBuilderRegistry();
    }

    /// @dev Call the Python signing script via FFI to get a real BLS signature.
    function _signFFI(string memory _fqdn, bytes32 _nonce)
        internal
        returns (bytes memory pubkey, bytes memory signature)
    {
        string[] memory cmd = new string[](6);
        cmd[0] = "python3";
        cmd[1] = "script/bls_sign.py";
        cmd[2] = vm.toString(block.chainid);
        cmd[3] = vm.toString(address(registry));
        cmd[4] = _fqdn;
        cmd[5] = vm.toString(_nonce);

        bytes memory result = vm.ffi(cmd);

        // Result is 304 bytes: 48-byte pubkey + 256-byte signature
        require(result.length == 304, "FFI output must be 304 bytes");

        pubkey = new bytes(48);
        signature = new bytes(256);

        assembly {
            // Copy 48 bytes of pubkey
            let src := add(result, 32)
            let dst := add(pubkey, 32)
            mstore(dst, mload(src))
            mstore(add(dst, 16), mload(add(src, 16)))
            // Only need 48 bytes but we copied 64; trim via length already set

            // Copy 256 bytes of signature
            src := add(add(result, 32), 48)
            dst := add(signature, 32)
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    /// @dev Convert 256-byte EIP-2537 signature to 192-byte Zcash format.
    /// EIP-2537: x_c0(64) || x_c1(64) || y_c0(64) || y_c1(64)
    /// Zcash:    x_c1(48) || x_c0(48) || y_c1(48) || y_c0(48)
    function _to192(bytes memory sig256) internal pure returns (bytes memory sig192) {
        sig192 = new bytes(192);
        assembly {
            let src := add(sig256, 32)
            let dst := add(sig192, 32)
            // x_c1: skip 16 zero-pad bytes from sig256[64:128]
            mcopy(dst, add(src, 80), 48)
            // x_c0: skip 16 zero-pad bytes from sig256[0:64]
            mcopy(add(dst, 48), add(src, 16), 48)
            // y_c1: skip 16 zero-pad bytes from sig256[192:256]
            mcopy(add(dst, 96), add(src, 208), 48)
            // y_c0: skip 16 zero-pad bytes from sig256[128:192]
            mcopy(add(dst, 144), add(src, 144), 48)
        }
    }

    function test_registerBuilder_validSignature_256() public {
        (bytes memory pubkey, bytes memory signature) = _signFFI(fqdn, nonce);

        vm.expectEmit();
        emit IBuilderRegistry.BuilderRegistered(pubkey, fqdn, nonce);

        registry.registerBuilder(pubkey, fqdn, nonce, signature);

        assertEq(registry.builderCount(0), 1);
        BuilderRecord memory r = registry.getBuilderAtIndex(0, 0);
        assertEq(r.pubkey, pubkey);
        assertEq(r.fqdn, fqdn);
    }

    function test_registerBuilder_validSignature_192() public {
        (bytes memory pubkey, bytes memory signature) = _signFFI(fqdn, nonce);
        bytes memory sig192 = _to192(signature);

        registry.registerBuilder(pubkey, fqdn, nonce, sig192);

        assertEq(registry.builderCount(0), 1);
        assertEq(registry.getBuilderAtIndex(0, 0).fqdn, fqdn);
    }

    function test_revert_registerBuilder_invalidSignature() public {
        (bytes memory pubkey, bytes memory signature) = _signFFI(fqdn, nonce);

        // Corrupt one byte of the signature
        signature[100] = signature[100] ^ 0xff;

        vm.expectRevert(OpenBuilderRegistry.SignatureVerificationFailed.selector);
        registry.registerBuilder(pubkey, fqdn, nonce, signature);
    }
}
