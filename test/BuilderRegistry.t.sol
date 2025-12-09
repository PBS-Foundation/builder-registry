// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/BuilderRegistry.sol";

contract BuilderRegistryTest is Test {
    BuilderRegistry registry;

    // Small constants are fine; they get zero-padded to 20 bytes
    address owner = address(0xA11CE);
    address curator1 = address(0xA12CE);
    address curator2 = address(0xA13CE);

    address builder1 = address(0xB001);
    address builder2 = address(0xB002);
    address builder3 = address(0xB003);

    function setUp() public {
        vm.prank(owner);
        registry = new BuilderRegistry();

        // sanity: constructor owner should be deployer
        assertEq(registry.owner(), owner);

        // register two curators
        vm.prank(owner);
        registry.registerCurator(curator1, "ipfs://curator1");

        vm.prank(owner);
        registry.registerCurator(curator2, "ipfs://curator2");
    }

    // --- Owner / curator basic behavior ---

    function testOwnerCanChangeOwner() public {
        address newOwner = address(0xDEAD);

        vm.prank(owner);
        registry.setOwner(newOwner);

        assertEq(registry.owner(), newOwner);
    }

    function testNonOwnerCannotRegisterCurator() public {
        vm.expectRevert("not owner");
        registry.registerCurator(address(0x1234), "meta");
    }

    function testCuratorIsRegisteredCorrectly() public {
        (bool exists, string memory uri) = registry.curators(curator1);
        assertTrue(exists);
        assertEq(uri, "ipfs://curator1");
    }

    function testUnregisterCurator() public {
        vm.prank(owner);
        registry.unregisterCurator(curator1);

        (bool exists,) = registry.curators(curator1);
        assertFalse(exists);
    }

    // --- Builder operations ---

    function _defaultBuilderInput(bool recommended, bool trustedPayment, bool trustlessPayment, bool ofacCompliant)
        internal
        pure
        returns (BuilderRegistry.BuilderInfo memory)
    {
        return BuilderRegistry.BuilderInfo({
            recommended: recommended,
            trustedPayment: trustedPayment,
            trustlessPayment: trustlessPayment,
            ofacCompliant: ofacCompliant
        });
    }

    function testCuratorCanSetBuilder() public {
        // curator1 adds builder1
        vm.prank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(
                true, // recommended
                true, // trustedPayment
                false, // trustlessPayment
                true // ofacCompliant
            )
        );

        (bool recommended, bool trustedPayment, bool trustlessPayment, bool ofacCompliant) =
            registry.buildersByCurator(curator1, builder1);

        assertTrue(registry.isBuilderRegistered(curator1, builder1));
        assertTrue(recommended);
        assertTrue(trustedPayment);
        assertFalse(trustlessPayment);
        assertTrue(ofacCompliant);
    }

    function testNonCuratorCannotSetBuilder() public {
        vm.expectRevert("not curator");
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, true, false));
    }

    function testCuratorCanUpdateBuilderFlags() public {
        // initial
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, false));

        // update: not recommended, now trustless & OFAC
        registry.setBuilder(builder1, _defaultBuilderInput(false, false, true, true));
        vm.stopPrank();

        (bool recommended, bool trustedPayment, bool trustlessPayment, bool ofacCompliant) =
            registry.buildersByCurator(curator1, builder1);

        assertTrue(registry.isBuilderRegistered(curator1, builder1));
        assertFalse(recommended);
        assertFalse(trustedPayment);
        assertTrue(trustlessPayment);
        assertTrue(ofacCompliant);
    }

    function testCuratorCanRemoveBuilder() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));
        registry.removeBuilder(builder1);
        vm.stopPrank();

        // Builder should be completely removed (swap-and-pop)
        assertFalse(registry.isBuilderRegistered(curator1, builder1));

        // Builder should not be in the list
        address[] memory all = registry.getAllBuilders(curator1);
        assertEq(all.length, 0);
    }

    function testNonCuratorCannotRemoveBuilder() public {
        vm.prank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));

        vm.prank(address(0xBAD));
        vm.expectRevert("not curator");
        registry.removeBuilder(builder1);
    }

    // --- Getter behavior ---

    function testGetAllBuilders() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));
        registry.setBuilder(builder2, _defaultBuilderInput(false, false, false, false));
        registry.setBuilder(builder3, _defaultBuilderInput(false, false, true, false));
        vm.stopPrank();

        address[] memory all = registry.getAllBuilders(curator1);
        // all existing
        assertEq(all.length, 3);
        // order: push sequence
        assertEq(all[0], builder1);
        assertEq(all[1], builder2);
        assertEq(all[2], builder3);
    }

    function testGetRecommendedBuilders() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));
        registry.setBuilder(builder2, _defaultBuilderInput(false, true, true, true));
        registry.setBuilder(builder3, _defaultBuilderInput(false, false, true, false));
        vm.stopPrank();

        BuilderRegistry.BuilderInfo memory filter = _defaultBuilderInput(true, false, false, false);
        uint8 filterMask = 0x01; // bit 0 = recommended
        address[] memory rec = registry.getBuildersByFilter(curator1, filter, filterMask);
        assertEq(rec.length, 1);
        assertEq(rec[0], builder1);
    }

    function testGetBuildersByFilterTrustedPayment() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));
        registry.setBuilder(builder2, _defaultBuilderInput(true, false, true, true));
        registry.setBuilder(builder3, _defaultBuilderInput(false, true, true, false));
        vm.stopPrank();

        // Use getBuildersByFilter with trustedPayment=true
        BuilderRegistry.BuilderInfo memory filter = _defaultBuilderInput(false, true, false, false);
        uint8 filterMask = 0x02; // bit 1 = trustedPayment
        address[] memory trustedOnly = registry.getBuildersByFilter(curator1, filter, filterMask);

        // builder1 and builder3 have trustedPayment
        assertEq(trustedOnly.length, 2);
        assertEq(trustedOnly[0], builder1);
        assertEq(trustedOnly[1], builder3);
    }

    function testGetBuildersByFilterTrustlessAndOFAC() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, true, true));
        registry.setBuilder(builder2, _defaultBuilderInput(true, true, true, false));
        registry.setBuilder(builder3, _defaultBuilderInput(false, false, true, true));
        vm.stopPrank();

        // Use getBuildersByFilter with trustlessPayment=true and ofacCompliant=true
        BuilderRegistry.BuilderInfo memory filter = _defaultBuilderInput(false, false, true, true);
        uint8 filterMask = 0x0C; // bit 2 = trustlessPayment, bit 3 = ofacCompliant
        address[] memory result = registry.getBuildersByFilter(curator1, filter, filterMask);

        // builder1 and builder3 match trustless + OFAC
        assertEq(result.length, 2);
        assertEq(result[0], builder1);
        assertEq(result[1], builder3);
    }

    function testSeparatedNamespacesPerCurator() public {
        // curator1: builder1
        vm.prank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));

        // curator2: builder2 only
        vm.prank(curator2);
        registry.setBuilder(builder2, _defaultBuilderInput(false, false, true, false));

        address[] memory list1 = registry.getAllBuilders(curator1);
        address[] memory list2 = registry.getAllBuilders(curator2);

        assertEq(list1.length, 1);
        assertEq(list1[0], builder1);

        assertEq(list2.length, 1);
        assertEq(list2[0], builder2);
    }

    function testRemoveBuilderDoesNotBreakGetAllBuilders() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true));
        registry.setBuilder(builder2, _defaultBuilderInput(false, true, true, false));
        vm.stopPrank();

        vm.prank(curator1);
        registry.removeBuilder(builder1);

        address[] memory all = registry.getAllBuilders(curator1);
        // Builder is completely removed using swap-and-pop
        assertEq(all.length, 1);
        assertEq(all[0], builder2);
        assertFalse(registry.isBuilderRegistered(curator1, builder1));
        assertTrue(registry.isBuilderRegistered(curator1, builder2));
    }
}
