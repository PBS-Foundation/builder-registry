// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/BuilderRegistry.sol";

contract BuilderRegistryTest is Test {
    BuilderRegistry registry;

    // Small constants are fine; they get zero-padded to 20 bytes
    address owner     = address(0xA11CE);
    address curator1  = address(0xA12CE);
    address curator2  = address(0xA13CE);

    address builder1  = address(0xB001);
    address builder2  = address(0xB002);
    address builder3  = address(0xB003);

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

        (bool exists, ) = registry.curators(curator1);
        assertFalse(exists);
    }

    // --- Builder operations ---

    function _defaultBuilderInput(
        bool active,
        bool recommended,
        bool trustedPayment,
        bool trustlessPayment,
        bool ofacCompliant,
        bool blobSupport
    ) internal pure returns (BuilderRegistry.BuilderInfoInput memory) {
        return BuilderRegistry.BuilderInfoInput({
            active: active,
            recommended: recommended,
            trustedPayment: trustedPayment,
            trustlessPayment: trustlessPayment,
            ofacCompliant: ofacCompliant,
            blobSupport: blobSupport
        });
    }

    function testCuratorCanSetBuilder() public {
        // curator1 adds builder1
        vm.prank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(
                true,   // active
                true,   // recommended
                true,   // trustedPayment
                false,  // trustlessPayment
                true,   // ofacCompliant
                true    // blobSupport
            )
        );

        (
            bool exists,
            bool active,
            bool recommended,
            bool trustedPayment,
            bool trustlessPayment,
            bool ofacCompliant,
            bool blobSupport
        ) = registry.buildersByCurator(curator1, builder1);

        assertTrue(exists);
        assertTrue(active);
        assertTrue(recommended);
        assertTrue(trustedPayment);
        assertFalse(trustlessPayment);
        assertTrue(ofacCompliant);
        assertTrue(blobSupport);
    }

    function testNonCuratorCannotSetBuilder() public {
        vm.expectRevert("not curator");
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, true, true, false, true, true)
        );
    }

    function testCuratorCanUpdateBuilderFlags() public {
        // initial
        vm.startPrank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, true, true, false, false, false)
        );

        // update: not recommended, now trustless & OFAC & blobSupport
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, false, false, true, true, true)
        );
        vm.stopPrank();

        (
            bool exists,
            bool active,
            bool recommended,
            bool trustedPayment,
            bool trustlessPayment,
            bool ofacCompliant,
            bool blobSupport
        ) = registry.buildersByCurator(curator1, builder1);

        assertTrue(exists);
        assertTrue(active);
        assertFalse(recommended);
        assertFalse(trustedPayment);
        assertTrue(trustlessPayment);
        assertTrue(ofacCompliant);
        assertTrue(blobSupport);
    }

    function testCuratorCanRemoveBuilder() public {
        vm.startPrank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, true, true, false, true, true)
        );
        registry.removeBuilder(builder1);
        vm.stopPrank();

        (
            bool exists,
            bool active,
            bool recommended,
            bool trustedPayment,
            bool trustlessPayment,
            bool ofacCompliant,
            bool blobSupport
        ) = registry.buildersByCurator(curator1, builder1);

        assertFalse(exists);
        assertFalse(active);
        assertFalse(recommended);
        assertFalse(trustedPayment);
        assertFalse(trustlessPayment);
        assertFalse(ofacCompliant);
        assertFalse(blobSupport);
    }

    function testNonCuratorCannotRemoveBuilder() public {
        vm.prank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, true, true, false, true, true)
        );

        vm.prank(address(0xBAD));
        vm.expectRevert("not curator");
        registry.removeBuilder(builder1);
    }

    // --- Getter behavior ---

    function testGetAllBuilders() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true,  true, false, true,  true));
        registry.setBuilder(builder2, _defaultBuilderInput(false, false, false, false, false, false));
        registry.setBuilder(builder3, _defaultBuilderInput(true, false, false, true,  false, true));
        vm.stopPrank();

        address[] memory all = registry.getAllBuilders(curator1);
        // all existing, regardless of active/recommended
        assertEq(all.length, 3);
        // order: push sequence
        assertEq(all[0], builder1);
        assertEq(all[1], builder2);
        assertEq(all[2], builder3);
    }

    function testGetActiveBuilders() public {
        vm.startPrank(curator1);
        // active + recommended
        registry.setBuilder(builder1, _defaultBuilderInput(true, true,  true, false, true,  true));
        // inactive
        registry.setBuilder(builder2, _defaultBuilderInput(false, true, true, false, true,  true));
        // active but not recommended
        registry.setBuilder(builder3, _defaultBuilderInput(true, false, false, true, false, true));
        vm.stopPrank();

        address[] memory active = registry.getActiveBuilders(curator1);
        assertEq(active.length, 2);

        // Should contain builder1 and builder3 (order preserved)
        assertEq(active[0], builder1);
        assertEq(active[1], builder3);
    }

    function testGetRecommendedBuilders() public {
        vm.startPrank(curator1);
        // active + recommended
        registry.setBuilder(builder1, _defaultBuilderInput(true, true,  true, false, true,  true));
        // inactive + recommended → should NOT appear
        registry.setBuilder(builder2, _defaultBuilderInput(false, true, true, false, true,  true));
        // active but not recommended
        registry.setBuilder(builder3, _defaultBuilderInput(true, false, false, true, false, true));
        vm.stopPrank();

        address[] memory rec = registry.getRecommendedBuilders(curator1);
        assertEq(rec.length, 1);
        assertEq(rec[0], builder1);
    }

    function testGetBuildersByFilterTrustedPayment() public {
        vm.startPrank(curator1);
        // active + trustedPayment
        registry.setBuilder(builder1, _defaultBuilderInput(true, true,  true,  false, true,  true));
        // active but not trustedPayment
        registry.setBuilder(builder2, _defaultBuilderInput(true, true,  false, true,  true,  true));
        // inactive + trustedPayment
        registry.setBuilder(builder3, _defaultBuilderInput(false, true, true,  false, true,  true));
        vm.stopPrank();

        address[] memory trustedOnly = registry.getBuildersByFilter(
            curator1,
            true,   // onlyTrustedPayment
            false,  // onlyTrustlessPayment
            false   // onlyOFAC
        );

        // only builder1 (active + trustedPayment)
        assertEq(trustedOnly.length, 1);
        assertEq(trustedOnly[0], builder1);
    }

    function testGetBuildersByFilterTrustlessAndOFAC() public {
        vm.startPrank(curator1);
        // active, trustless, OFAC
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, false, true,  true,  true));
        // active, trustless, non-OFAC
        registry.setBuilder(builder2, _defaultBuilderInput(true, true, false, true,  false, true));
        // inactive, trustless, OFAC
        registry.setBuilder(builder3, _defaultBuilderInput(false, true, false, true,  true,  true));
        vm.stopPrank();

        address[] memory result = registry.getBuildersByFilter(
            curator1,
            false,  // onlyTrustedPayment
            true,   // onlyTrustlessPayment
            true    // onlyOFAC
        );

        // only builder1 matches all three conditions
        assertEq(result.length, 1);
        assertEq(result[0], builder1);
    }

    function testSeparatedNamespacesPerCurator() public {
        // curator1: builder1
        vm.prank(curator1);
        registry.setBuilder(
            builder1,
            _defaultBuilderInput(true, true, true, false, true, true)
        );

        // curator2: builder2 only
        vm.prank(curator2);
        registry.setBuilder(
            builder2,
            _defaultBuilderInput(true, true, false, true, false, true)
        );

        address[] memory list1 = registry.getAllBuilders(curator1);
        address[] memory list2 = registry.getAllBuilders(curator2);

        assertEq(list1.length, 1);
        assertEq(list1[0], builder1);

        assertEq(list2.length, 1);
        assertEq(list2[0], builder2);
    }

    function testRemoveBuilderDoesNotBreakGetAllBuilders() public {
        vm.startPrank(curator1);
        registry.setBuilder(builder1, _defaultBuilderInput(true, true, true, false, true, true));
        registry.setBuilder(builder2, _defaultBuilderInput(true, true, true, false, true, true));
        vm.stopPrank();

        vm.prank(curator1);
        registry.removeBuilder(builder1);

        address[] memory all = registry.getAllBuilders(curator1);
        // internal array still len=2, but exists==true only for builder2
        assertEq(all.length, 1);
        assertEq(all[0], builder2);
    }
}
