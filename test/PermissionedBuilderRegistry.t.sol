// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BuilderRecord} from "../src/interfaces/IERC8218.sol";
import {PermissionedBuilderRegistry} from "../src/PermissionedBuilderRegistry.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

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

        pk1 = new bytes(48);
        pk1[0] = 0x01;
        pk2 = new bytes(48);
        pk2[0] = 0x02;
        pk3 = new bytes(48);
        pk3[0] = 0x03;
    }

    function testOwnerCanRegisterBuilder() public {
        vm.prank(owner);
        registry.registerBuilder(pk1, "builder1.example.com");

        assertTrue(registry.isBuilderRegistered(pk1));
        assertEq(registry.builderCount(), 1);

        BuilderRecord memory record = registry.getBuilderAtIndex(0);
        assertEq(record.pubkey, pk1);
        assertEq(record.fqdn, "builder1.example.com");
    }

    function testNonOwnerCannotRegisterBuilder() public {
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, outsider));
        registry.registerBuilder(pk1, "builder1.example.com");
    }

    function testOwnerCanUpdateBuilderFqdn() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "old.example.com");
        registry.registerBuilder(pk1, "new.example.com");
        vm.stopPrank();

        assertEq(registry.builderCount(), 1);
        assertEq(registry.getBuilderAtIndex(0).fqdn, "new.example.com");
    }

    function testOwnerCanDeregisterBuilder() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "builder1.example.com");
        registry.deregisterBuilder(pk1);
        vm.stopPrank();

        assertEq(registry.builderCount(), 0);
        assertFalse(registry.isBuilderRegistered(pk1));
    }

    function testNonOwnerCannotDeregisterBuilder() public {
        vm.prank(owner);
        registry.registerBuilder(pk1, "builder1.example.com");

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, outsider));
        registry.deregisterBuilder(pk1);
    }

    function testDeregisterUsesSwapAndPop() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "first.example.com");
        registry.registerBuilder(pk2, "second.example.com");
        registry.registerBuilder(pk3, "third.example.com");
        registry.deregisterBuilder(pk1);
        vm.stopPrank();

        assertEq(registry.builderCount(), 2);
        assertEq(registry.getBuilderAtIndex(0).fqdn, "third.example.com");
        assertEq(registry.getBuilderAtIndex(1).fqdn, "second.example.com");
    }

    function testRevertInvalidPubkeyLengthOnRegister() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(PermissionedBuilderRegistry.InvalidPubkeyLength.selector, 47));
        registry.registerBuilder(new bytes(47), "builder1.example.com");
    }

    function testRevertEmptyFqdnOnRegister() public {
        vm.prank(owner);
        vm.expectRevert(PermissionedBuilderRegistry.EmptyFQDN.selector);
        registry.registerBuilder(pk1, "");
    }

    function testRevertNotRegisteredOnDeregister() public {
        vm.prank(owner);
        vm.expectRevert(PermissionedBuilderRegistry.NotRegistered.selector);
        registry.deregisterBuilder(pk1);
    }

    function testBuilderCount() public {
        vm.startPrank(owner);
        registry.registerBuilder(pk1, "builder1.example.com");
        registry.registerBuilder(pk2, "builder2.example.com");
        vm.stopPrank();

        assertEq(registry.builderCount(), 2);
    }
}
