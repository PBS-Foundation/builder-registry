// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BuilderRecord, IBuilderList} from "../src/interfaces/IERC8218.sol";
import {BuilderListBase} from "../src/BuilderListBase.sol";
import {OpenBuilderRegistry} from "../src/OpenBuilderRegistry.sol";

/// @dev Harness that exposes direct writes for unit testing the list
/// interface without needing valid BLS signatures.
contract OpenBuilderRegistryHarness is OpenBuilderRegistry {
    function directInsert(
        bytes calldata pubkey,
        string calldata url,
        bytes calldata authData
    ) external {
        _upsert(keccak256(pubkey), pubkey, url, authData);
    }

    function checkEndpoint(
        string calldata url,
        bytes calldata authData
    ) external pure {
        _validateEndpoint(url, authData);
    }

    function directRemove(bytes calldata pubkey) external {
        bytes32 pkHash = keccak256(pubkey);
        _remove(pkHash, _requireIndex(pkHash), pubkey);
    }
}

/// @notice Tests input validation (pubkey, URL, auth data, signature length).
contract OpenBuilderRegistry_ValidationTest is Test {
    OpenBuilderRegistry registry;

    bytes validPubkey = new bytes(48);
    bytes validSignature = new bytes(256);
    string constant URL = "https://builder.example.com:18550";

    function setUp() public {
        registry = new OpenBuilderRegistry();
        validPubkey[0] = 0x80; // compression flag
    }

    function _repeat(
        bytes1 c,
        uint256 n
    ) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = c;
        }
    }

    function test_revert_InvalidPubkeyLength_tooShort() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                BuilderListBase.InvalidPubkeyLength.selector,
                47
            )
        );
        registry.registerBuilder(new bytes(47), URL, "", 1, validSignature);
    }

    function test_revert_InvalidPubkeyLength_tooLong() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                BuilderListBase.InvalidPubkeyLength.selector,
                49
            )
        );
        registry.registerBuilder(new bytes(49), URL, "", 1, validSignature);
    }

    function test_revert_InvalidPubkeyEncoding_notCompressed() public {
        bytes memory pk = new bytes(48);
        vm.expectRevert(BuilderListBase.InvalidPubkeyEncoding.selector);
        registry.registerBuilder(pk, URL, "", 1, validSignature);
    }

    function test_revert_InvalidPubkeyEncoding_infinity() public {
        bytes memory pk = new bytes(48);
        pk[0] = 0xc0; // compressed + infinity
        vm.expectRevert(BuilderListBase.InvalidPubkeyEncoding.selector);
        registry.registerBuilder(pk, URL, "", 1, validSignature);
    }

    function test_revert_EmptyURL() public {
        vm.expectRevert(BuilderListBase.EmptyURL.selector);
        registry.registerBuilder(validPubkey, "", "", 1, validSignature);
    }

    function test_revert_URLTooLong() public {
        uint256 tooLong = registry.MAX_URL_LENGTH() + 1;
        string memory url = string.concat(
            "https://",
            string(_repeat("a", tooLong - 8))
        );
        vm.expectRevert(
            abi.encodeWithSelector(BuilderListBase.URLTooLong.selector, tooLong)
        );
        registry.registerBuilder(validPubkey, url, "", 1, validSignature);
    }

    function test_accept_URLAtMaxLength() public {
        uint256 maxLen = registry.MAX_URL_LENGTH();
        string memory url = string.concat(
            "https://",
            string(_repeat("a", maxLen - 8))
        );
        // Passes validation and fails later at BLS verification.
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(validPubkey, url, "", 1, validSignature);
    }

    function test_revert_InvalidURL() public {
        string[14] memory bad = [
            "builder.example.com",
            "http://builder.example.com",
            "HTTPS://builder.example.com",
            "https://",
            "https:///eth",
            "https://:18550",
            "https://user:pw@builder.example.com",
            "https://builder.example.com/?x=1",
            "https://builder.example.com/#frag",
            "https://builder example.com",
            "https://builder.example.com\\x",
            "https://builder.example.com\n",
            unicode"https://bücher.example",
            "ftp://builder.example.com"
        ];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(BuilderListBase.InvalidURL.selector);
            registry.registerBuilder(
                validPubkey,
                bad[i],
                "",
                1,
                validSignature
            );
        }
    }

    function test_accept_validURLs() public {
        OpenBuilderRegistryHarness h = new OpenBuilderRegistryHarness();
        string[5] memory good = [
            "https://builder.example.com",
            "https://builder.example.com/",
            "https://builder.example.com:18550",
            "https://10.0.0.5:18550/prefix",
            "https://[::1]:8443"
        ];
        for (uint256 i = 0; i < good.length; i++) {
            h.checkEndpoint(good[i], "");
        }
    }

    function test_revert_AuthDataTooLong() public {
        uint256 tooLong = registry.MAX_AUTH_DATA_LENGTH() + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                BuilderListBase.AuthDataTooLong.selector,
                tooLong
            )
        );
        registry.registerBuilder(
            validPubkey,
            URL,
            new bytes(tooLong),
            1,
            validSignature
        );
    }

    function test_accept_AuthDataAtMaxLength() public {
        bytes memory authData = new bytes(registry.MAX_AUTH_DATA_LENGTH());
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(validPubkey, URL, authData, 1, validSignature);
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
                abi.encodeWithSelector(
                    OpenBuilderRegistry.InvalidSignatureLength.selector,
                    badLengths[i]
                )
            );
            registry.registerBuilder(
                validPubkey,
                URL,
                "",
                1,
                new bytes(badLengths[i])
            );
        }
    }

    function test_accept_SignatureLength_192() public {
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(validPubkey, URL, "", 1, new bytes(192));
    }

    function test_accept_SignatureLength_256() public {
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(validPubkey, URL, "", 1, validSignature);
    }

    function test_revert_StaleNonce_zero() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                OpenBuilderRegistry.StaleNonce.selector,
                0,
                0
            )
        );
        registry.registerBuilder(validPubkey, URL, "", 0, validSignature);
    }

    function test_revert_deregister_InvalidPubkeyEncoding() public {
        vm.expectRevert(BuilderListBase.InvalidPubkeyEncoding.selector);
        registry.deregisterBuilder(new bytes(48), 1, validSignature);
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
        pk1[0] = 0x81;
        pk2 = new bytes(48);
        pk2[0] = 0x82;
        pk3 = new bytes(48);
        pk3[0] = 0x83;
    }

    function test_builderCount_empty() public view {
        assertEq(registry.builderCount(), 0);
    }

    function test_builderCount_afterInserts() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directInsert(pk2, "https://b.example.com", "");
        assertEq(registry.builderCount(), 2);
    }

    function test_getBuilderAtIndex_returnsCorrectRecord() public {
        vm.warp(1_700_000_000);
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directInsert(
            pk2,
            "https://b.example.com:18550",
            "custom-auth"
        );

        BuilderRecord memory r0 = registry.getBuilderAtIndex(0);
        assertEq(r0.pubkey, pk1);
        assertEq(r0.url, "https://a.example.com");
        assertEq(r0.authData, "");
        assertEq(r0.updatedAt, 1_700_000_000);

        BuilderRecord memory r1 = registry.getBuilderAtIndex(1);
        assertEq(r1.pubkey, pk2);
        assertEq(r1.url, "https://b.example.com:18550");
        assertEq(r1.authData, "custom-auth");
    }

    function test_revert_getBuilderAtIndex_outOfBounds() public {
        vm.expectRevert(BuilderListBase.IndexOutOfBounds.selector);
        registry.getBuilderAtIndex(0);
    }

    function test_revert_getBuilderAtIndex_exactBoundary() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        vm.expectRevert(BuilderListBase.IndexOutOfBounds.selector);
        registry.getBuilderAtIndex(1);
    }

    function test_getBuilder_byPubkey() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directInsert(pk2, "https://b.example.com", "x");

        BuilderRecord memory r = registry.getBuilder(pk2);
        assertEq(r.pubkey, pk2);
        assertEq(r.url, "https://b.example.com");
        assertEq(r.authData, "x");
        assertTrue(registry.isBuilderRegistered(pk2));
        assertFalse(registry.isBuilderRegistered(pk3));
    }

    function test_revert_getBuilder_notRegistered() public {
        vm.expectRevert(BuilderListBase.NotRegistered.selector);
        registry.getBuilder(pk1);
    }

    function test_getBuilders_pagination() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directInsert(pk2, "https://b.example.com", "");
        registry.directInsert(pk3, "https://c.example.com", "");

        BuilderRecord[] memory all = registry.getBuilders(0, 10);
        assertEq(all.length, 3);
        assertEq(all[2].url, "https://c.example.com");

        BuilderRecord[] memory mid = registry.getBuilders(1, 1);
        assertEq(mid.length, 1);
        assertEq(mid[0].url, "https://b.example.com");

        BuilderRecord[] memory tail = registry.getBuilders(2, 5);
        assertEq(tail.length, 1);
        assertEq(tail[0].url, "https://c.example.com");

        assertEq(registry.getBuilders(3, 5).length, 0);
        assertEq(registry.getBuilders(0, 0).length, 0);
        assertEq(registry.getBuilders(1, type(uint256).max).length, 2);
        assertEq(
            registry.getBuilders(type(uint256).max, type(uint256).max).length,
            0
        );
    }

    function testFuzz_getBuilders_matchesIndexAccess(
        uint8 n,
        uint8 offset,
        uint8 limit
    ) public {
        n = uint8(bound(n, 0, 20));
        for (uint256 i = 0; i < n; i++) {
            bytes memory pk = new bytes(48);
            pk[0] = 0x80;
            pk[47] = bytes1(uint8(i));
            registry.directInsert(
                pk,
                string.concat("https://b", vm.toString(i), ".example.com"),
                ""
            );
        }
        BuilderRecord[] memory page = registry.getBuilders(offset, limit);
        uint256 expected = offset >= n
            ? 0
            : (n - offset < limit ? n - offset : limit);
        assertEq(page.length, expected);
        for (uint256 i = 0; i < page.length; i++) {
            assertEq(
                page[i].pubkey,
                registry.getBuilderAtIndex(offset + i).pubkey
            );
        }
    }

    function test_update_overwritesRecordAndTimestamp() public {
        vm.warp(1000);
        registry.directInsert(pk1, "https://old.example.com", "old");
        vm.warp(2000);
        registry.directInsert(pk1, "https://new.example.com", "");
        assertEq(registry.builderCount(), 1);

        BuilderRecord memory r = registry.getBuilderAtIndex(0);
        assertEq(r.url, "https://new.example.com");
        assertEq(r.authData, "");
        assertEq(r.updatedAt, 2000);
    }

    function test_events() public {
        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderRegistered(
            keccak256(pk1),
            pk1,
            "https://a.example.com",
            "d"
        );
        registry.directInsert(pk1, "https://a.example.com", "d");

        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderDeregistered(keccak256(pk1), pk1);
        registry.directRemove(pk1);
    }

    function test_directRemove_single() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directRemove(pk1);
        assertEq(registry.builderCount(), 0);
        assertFalse(registry.isBuilderRegistered(pk1));
    }

    function test_directRemove_swapAndPop() public {
        registry.directInsert(pk1, "https://first.example.com", "");
        registry.directInsert(pk2, "https://second.example.com", "");
        registry.directInsert(pk3, "https://third.example.com", "");

        // Remove pk1 (index 0) — pk3 should swap into its place
        registry.directRemove(pk1);
        assertEq(registry.builderCount(), 2);
        assertEq(
            registry.getBuilderAtIndex(0).url,
            "https://third.example.com"
        );
        assertEq(
            registry.getBuilderAtIndex(1).url,
            "https://second.example.com"
        );
        // Lookup by pubkey still resolves the moved record.
        assertEq(registry.getBuilder(pk3).url, "https://third.example.com");
    }

    function test_directRemove_last() public {
        registry.directInsert(pk1, "https://first.example.com", "");
        registry.directInsert(pk2, "https://second.example.com", "");

        registry.directRemove(pk2);
        assertEq(registry.builderCount(), 1);
        assertEq(
            registry.getBuilderAtIndex(0).url,
            "https://first.example.com"
        );
    }

    function test_directRemove_thenReinsert() public {
        registry.directInsert(pk1, "https://a.example.com", "");
        registry.directRemove(pk1);
        registry.directInsert(pk1, "https://b.example.com", "");
        assertEq(registry.builderCount(), 1);
        assertEq(registry.getBuilderAtIndex(0).url, "https://b.example.com");
    }
}

/// @notice Full registration flow with real BLS signatures (no mocks).
/// @dev Uses FFI to call a Python script that generates real BLS12-381 signatures
/// via py_ecc. All precompiles (G1 decompression, hash-to-curve, pairing)
/// are exercised with real cryptographic inputs.
contract OpenBuilderRegistry_RegistrationTest is Test {
    OpenBuilderRegistry registry;

    string url = "https://builder.example.com:18550";
    bytes authData = "";

    function setUp() public {
        registry = new OpenBuilderRegistry();
    }

    function _split(
        bytes memory result
    ) internal pure returns (bytes memory pubkey, bytes memory signature) {
        // Result is 304 bytes: 48-byte pubkey + 256-byte signature
        require(result.length == 304, "FFI output must be 304 bytes");
        pubkey = new bytes(48);
        signature = new bytes(256);
        assembly {
            mcopy(add(pubkey, 32), add(result, 32), 48)
            mcopy(add(signature, 32), add(result, 80), 256)
        }
    }

    /// @dev Call the Python signing script via FFI to get a real registration signature.
    function _signRegisterFFI(
        string memory _url,
        bytes memory _authData,
        uint64 _nonce
    ) internal returns (bytes memory pubkey, bytes memory signature) {
        string[] memory cmd = new string[](8);
        cmd[0] = "python3";
        cmd[1] = "script/bls_sign.py";
        cmd[2] = vm.toString(block.chainid);
        cmd[3] = vm.toString(address(registry));
        cmd[4] = "--register";
        cmd[5] = _url;
        cmd[6] = vm.toString(_authData);
        cmd[7] = vm.toString(uint256(_nonce));
        return _split(vm.ffi(cmd));
    }

    /// @dev Call the Python signing script in deregister mode via FFI.
    function _signDeregisterFFI(
        uint64 _nonce
    ) internal returns (bytes memory pubkey, bytes memory signature) {
        string[] memory cmd = new string[](6);
        cmd[0] = "python3";
        cmd[1] = "script/bls_sign.py";
        cmd[2] = vm.toString(block.chainid);
        cmd[3] = vm.toString(address(registry));
        cmd[4] = "--deregister";
        cmd[5] = vm.toString(uint256(_nonce));
        return _split(vm.ffi(cmd));
    }

    /// @dev Convert 256-byte EIP-2537 signature to 192-byte Zcash format.
    /// EIP-2537: x_c0(64) || x_c1(64) || y_c0(64) || y_c1(64)
    /// Zcash:    x_c1(48) || x_c0(48) || y_c1(48) || y_c0(48)
    function _to192(
        bytes memory sig256
    ) internal pure returns (bytes memory sig192) {
        sig192 = new bytes(192);
        assembly {
            let src := add(sig256, 32)
            let dst := add(sig192, 32)
            mcopy(dst, add(src, 80), 48)
            mcopy(add(dst, 48), add(src, 16), 48)
            mcopy(add(dst, 96), add(src, 208), 48)
            mcopy(add(dst, 144), add(src, 144), 48)
        }
    }

    function test_registerBuilder_validSignature_256() public {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );

        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderRegistered(
            keccak256(pubkey),
            pubkey,
            url,
            authData
        );

        registry.registerBuilder(pubkey, url, authData, 1, signature);

        assertEq(registry.builderCount(), 1);
        assertEq(registry.nonces(pubkey), 1);
        BuilderRecord memory r = registry.getBuilder(pubkey);
        assertEq(r.pubkey, pubkey);
        assertEq(r.url, url);
        assertEq(r.updatedAt, uint64(block.timestamp));
    }

    function test_registerBuilder_validSignature_192() public {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );
        registry.registerBuilder(pubkey, url, authData, 1, _to192(signature));
        assertEq(registry.getBuilderAtIndex(0).url, url);
    }

    function test_registerBuilder_withCustomAuthData() public {
        bytes memory custom = "builder-a.shared-host.example";
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            custom,
            1
        );
        registry.registerBuilder(pubkey, url, custom, 1, signature);
        assertEq(registry.getBuilder(pubkey).authData, custom);
    }

    function test_revert_registerBuilder_tamperedAuthData() public {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(pubkey, url, "attacker", 1, signature);
    }

    function test_revert_registerBuilder_tamperedNonce() public {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );
        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(pubkey, url, authData, 2, signature);
    }

    function test_revert_registerBuilder_replaySameNonce() public {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );
        registry.registerBuilder(pubkey, url, authData, 1, signature);

        vm.expectRevert(
            abi.encodeWithSelector(
                OpenBuilderRegistry.StaleNonce.selector,
                1,
                1
            )
        );
        registry.registerBuilder(pubkey, url, authData, 1, signature);
    }

    /// @dev A registration signed earlier but landing later must not roll back a newer one.
    function test_revert_registerBuilder_outOfOrderRollback() public {
        string memory oldUrl = "https://old.example.com";
        (bytes memory pubkey, bytes memory oldSig) = _signRegisterFFI(
            oldUrl,
            authData,
            1
        );
        (, bytes memory newSig) = _signRegisterFFI(url, authData, 2);

        registry.registerBuilder(pubkey, url, authData, 2, newSig);

        vm.expectRevert(
            abi.encodeWithSelector(
                OpenBuilderRegistry.StaleNonce.selector,
                1,
                2
            )
        );
        registry.registerBuilder(pubkey, oldUrl, authData, 1, oldSig);
        assertEq(registry.getBuilder(pubkey).url, url);
    }

    function test_registerBuilder_updateWithHigherNonce() public {
        (bytes memory pubkey, bytes memory sig1) = _signRegisterFFI(
            "https://old.example.com",
            authData,
            1
        );
        registry.registerBuilder(
            pubkey,
            "https://old.example.com",
            authData,
            1,
            sig1
        );

        // Nonces need not be contiguous.
        (, bytes memory sig2) = _signRegisterFFI(url, authData, 10);
        registry.registerBuilder(pubkey, url, authData, 10, sig2);

        assertEq(registry.builderCount(), 1);
        assertEq(registry.getBuilder(pubkey).url, url);
        assertEq(registry.nonces(pubkey), 10);
    }

    function test_deregisterBuilder_validSignature() public {
        (bytes memory pubkey, bytes memory regSig) = _signRegisterFFI(
            url,
            authData,
            1
        );
        registry.registerBuilder(pubkey, url, authData, 1, regSig);

        (, bytes memory deregSig) = _signDeregisterFFI(2);

        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderDeregistered(keccak256(pubkey), pubkey);

        registry.deregisterBuilder(pubkey, 2, deregSig);
        assertEq(registry.builderCount(), 0);
        assertFalse(registry.isBuilderRegistered(pubkey));
        assertEq(registry.nonces(pubkey), 2);
    }

    /// @dev After deregistration the old registration signature must not re-add the builder.
    function test_revert_replayRegistrationAfterDeregister() public {
        (bytes memory pubkey, bytes memory regSig) = _signRegisterFFI(
            url,
            authData,
            1
        );
        registry.registerBuilder(pubkey, url, authData, 1, regSig);
        (, bytes memory deregSig) = _signDeregisterFFI(2);
        registry.deregisterBuilder(pubkey, 2, deregSig);

        vm.expectRevert(
            abi.encodeWithSelector(
                OpenBuilderRegistry.StaleNonce.selector,
                1,
                2
            )
        );
        registry.registerBuilder(pubkey, url, authData, 1, regSig);

        // A fresh registration with a higher nonce works.
        (, bytes memory regSig3) = _signRegisterFFI(url, authData, 3);
        registry.registerBuilder(pubkey, url, authData, 3, regSig3);
        assertTrue(registry.isBuilderRegistered(pubkey));
    }

    function test_revert_deregisterBuilder_staleNonce() public {
        (bytes memory pubkey, bytes memory regSig) = _signRegisterFFI(
            url,
            authData,
            5
        );
        registry.registerBuilder(pubkey, url, authData, 5, regSig);
        (, bytes memory deregSig) = _signDeregisterFFI(4);

        vm.expectRevert(
            abi.encodeWithSelector(
                OpenBuilderRegistry.StaleNonce.selector,
                4,
                5
            )
        );
        registry.deregisterBuilder(pubkey, 4, deregSig);
    }

    function test_revert_deregisterBuilder_notRegistered() public {
        (bytes memory pubkey, bytes memory deregSig) = _signDeregisterFFI(2);
        vm.expectRevert(BuilderListBase.NotRegistered.selector);
        registry.deregisterBuilder(pubkey, 2, deregSig);
    }

    function test_revert_registerBuilder_invalidSignature_doesNotConsumeNonce()
        public
    {
        (bytes memory pubkey, bytes memory signature) = _signRegisterFFI(
            url,
            authData,
            1
        );
        signature[100] = signature[100] ^ 0xff;

        vm.expectRevert(
            OpenBuilderRegistry.SignatureVerificationFailed.selector
        );
        registry.registerBuilder(pubkey, url, authData, 1, signature);
        assertEq(registry.nonces(pubkey), 0);
    }
}
