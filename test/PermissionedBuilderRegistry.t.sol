// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BuilderRecord, IBuilderList} from "../src/interfaces/IERC8218.sol";
import {BuilderListBase} from "../src/BuilderListBase.sol";
import {PermissionedBuilderRegistry} from "../src/PermissionedBuilderRegistry.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {BLS12381} from "../src/lib/BLS12381.sol";

contract PermissionedBuilderRegistryTest is Test {
    PermissionedBuilderRegistry registry;

    address owner = address(0xA11CE);
    address outsider = address(0xBAD);

    bytes pk1;
    bytes pk2;
    bytes pk3;

    function setUp() public {
        vm.prank(owner);
        registry = new PermissionedBuilderRegistry();

        // Valid BLS12-381 pubkeys generated with py_ecc.
        pk1 = hex"97d7ff59198253b30a60fbc653cf89c9c45dda1161e62df522403001080ebb575b10f292b9ed9dfd39935eb23bca8f09";
        pk2 = hex"ae1d4d7c851c3d73bc17066a32b33d69512db9d22175e2ca8e77f7b9b2db7dfad63aff1400c6ae0145daaa6dd8f7c229";
        pk3 = hex"aaa9b36944e60dcf5c5036122c28eda5a621303b23d19bda5a68a25713e800bdfbb47341f1978656fd8ed9c546b08d51";
    }

    function testOwnerCanRegisterBuilder() public {
        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderRegistered(keccak256(pk1), pk1, "https://builder1.example.com", "");

        vm.prank(owner);
        registry.registerBuilder(pk1, "https://builder1.example.com", "");

        assertTrue(registry.isBuilderRegistered(pk1));
        assertEq(registry.builderCount(), 1);

        BuilderRecord memory record = registry.getBuilderAtIndex(0);
        assertEq(record.pubkey, pk1);
        assertEq(record.url, "https://builder1.example.com");
        assertEq(record.updatedAt, uint64(block.timestamp));
    }

    function testNonOwnerCannotRegisterBuilder() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, outsider));
        registry.registerBuilder(pk1, "https://builder1.example.com", "");
    }

    function testOwnerCanUpdateBuilderRecord() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "https://old.example.com", "");
        registry.registerBuilder(pk1, "https://new.example.com:18550", "custom");
        vm.stopPrank();

        assertEq(registry.builderCount(), 1);
        BuilderRecord memory r = registry.getBuilder(pk1);
        assertEq(r.url, "https://new.example.com:18550");
        assertEq(r.authData, "custom");
    }

    function testOwnerCanDeregisterBuilder() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "https://builder1.example.com", "");

        vm.expectEmit(true, false, false, true);
        emit IBuilderList.BuilderDeregistered(keccak256(pk1), pk1);
        registry.deregisterBuilder(pk1);
        vm.stopPrank();

        assertEq(registry.builderCount(), 0);
        assertFalse(registry.isBuilderRegistered(pk1));
    }

    function testNonOwnerCannotDeregisterBuilder() public {
        vm.prank(owner);
        registry.registerBuilder(pk1, "https://builder1.example.com", "");

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, outsider));
        registry.deregisterBuilder(pk1);
    }

    function testDeregisterUsesSwapAndPop() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "https://first.example.com", "");
        registry.registerBuilder(pk2, "https://second.example.com", "");
        registry.registerBuilder(pk3, "https://third.example.com", "");
        registry.deregisterBuilder(pk1);
        vm.stopPrank();

        assertEq(registry.builderCount(), 2);
        assertEq(registry.getBuilderAtIndex(0).url, "https://third.example.com");
        assertEq(registry.getBuilderAtIndex(1).url, "https://second.example.com");
        assertEq(registry.getBuilders(0, 10).length, 2);
    }

    function testRevertInvalidPubkeyLengthOnRegister() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(BuilderListBase.InvalidPubkeyLength.selector, 47));
        registry.registerBuilder(new bytes(47), "https://builder1.example.com", "");
    }

    function testRevertInfinityPubkeyOnRegister() public {
        bytes memory pk = new bytes(48);
        pk[0] = 0xc0;
        vm.prank(owner);
        vm.expectRevert(BuilderListBase.InvalidPubkeyEncoding.selector);
        registry.registerBuilder(pk, "https://builder1.example.com", "");
    }

    function testRevertEmptyUrlOnRegister() public {
        vm.prank(owner);
        vm.expectRevert(BuilderListBase.EmptyURL.selector);
        registry.registerBuilder(pk1, "", "");
    }

    function testRevertBareHostnameOnRegister() public {
        vm.prank(owner);
        vm.expectRevert(BuilderListBase.InvalidURL.selector);
        registry.registerBuilder(pk1, "builder1.example.com", "");
    }

    function testRevertNotRegisteredOnDeregister() public {
        vm.prank(owner);
        vm.expectRevert(BuilderListBase.NotRegistered.selector);
        registry.deregisterBuilder(pk1);
    }

    function testTwoStepOwnershipTransfer() public {
        vm.prank(owner);
        registry.transferOwnership(outsider);
        // Ownership does not move until accepted.
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), outsider);

        vm.prank(outsider);
        registry.acceptOwnership();
        assertEq(registry.owner(), outsider);
    }

    // ---------------------------------------------------------------------
    // Invalid BLS public keys (vectors generated with py_ecc)
    // ---------------------------------------------------------------------

    function _register(bytes memory pk) internal {
        vm.prank(owner);
        registry.registerBuilder(pk, "https://builder.example.com", "");
    }

    function testRevertPubkeyNotOnCurve() public {
        // x = 1: x^3 + 4 is not a square mod p.
        vm.expectRevert(BLS12381.NotOnCurve.selector);
        _register(hex"800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");
    }

    function testRevertPubkeyNotInSubgroup() public {
        // x = 4: on the curve, but not in the prime-order G1 subgroup.
        vm.expectRevert(BLS12381.NotInSubgroup.selector);
        _register(hex"800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004");
    }

    function testRevertWhenG1MSMPrecompileIsUnavailable() public {
        vm.mockCall(address(0x0c), bytes(""), bytes(""));
        vm.expectRevert(BLS12381.NotInSubgroup.selector);
        _register(pk1);
    }

    function testRevertPubkeyXEqualsModulus() public {
        vm.expectRevert(BLS12381.NonCanonicalFieldElement.selector);
        _register(hex"9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    }

    /// @dev The same key encoded as x and as x + p must not produce two entries.
    function testRevertNonCanonicalDuplicateOfValidKey() public {
        bytes memory canonical =
            hex"85a5756c9b93d6fcd2d2614b08ebe428c0b4c6101596ff7cd3a7fe75910193dbcfaf8c441fcd2627d02a65860c944443";
        bytes memory nonCanonical =
            hex"9fa68756d513bd971dee09014c379100252c1195091c123c3ad8d11687b289ffee5b8c42d12126278a2965860c93eeee";

        _register(canonical);
        assertTrue(registry.isBuilderRegistered(canonical));

        vm.expectRevert(BLS12381.NonCanonicalFieldElement.selector);
        _register(nonCanonical);
        assertEq(registry.builderCount(), 1);
    }

    function testRevertPubkeyNotCompressed() public {
        vm.expectRevert(BuilderListBase.InvalidPubkeyEncoding.selector);
        _register(new bytes(48));
    }

    /// @dev An invalid point must not consume the caller's whole gas budget.
    function testInvalidPubkeyGasIsBounded() public {
        uint256 before = gasleft();
        vm.prank(owner);
        try registry.registerBuilder(
            hex"800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004",
            "https://builder.example.com",
            ""
        ) {
            fail();
        } catch {}
        assertLt(before - gasleft(), 200_000);
    }
}
