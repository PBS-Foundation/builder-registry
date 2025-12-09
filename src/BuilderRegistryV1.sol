// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BuilderRegistryV1
 * @notice On-chain registry for validator in EPBS.
 */
contract BuilderRegistryV1 {
    /// @notice The owner of the contract, typically a multisig Safe
    address public owner;

    /**
     * @notice Metadata structure for a builder
     * @param recommended Whether the builder is recommended for use
     * @param trustedPayment Whether the builder supports trusted payments
     * @param trustlessPayment Whether the builder supports trustless payments
     * @param ofacCompliant Whether the builder is OFAC compliant
     */
    struct BuilderInfo {
        bool recommended;
        bool trustedPayment;
        bool trustlessPayment;
        bool ofacCompliant;
    }

    /// @notice Mapping from builder address to their metadata
    mapping(address => BuilderInfo) public builders;

    /// @notice List of all registered builder addresses for iteration
    address[] public builderList;

    /// @notice Mapping from builder address to their index in builderList + 1
    /// @dev We store index + 1 so that 0 means "not in list"
    mapping(address => uint256) private builderIndex;

    /**
     * @notice Emitted when the contract owner is changed
     * @param oldOwner The previous owner address
     * @param newOwner The new owner address
     */
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    /**
     * @notice Emitted when a builder's information is set or updated
     * @param builder The address of the builder
     * @param recommended Whether the builder is recommended
     * @param trustedPayment Whether the builder supports trusted payments
     * @param trustlessPayment Whether the builder supports trustless payments
     * @param ofacCompliant Whether the builder is OFAC compliant
     */
    event BuilderSet(
        address indexed builder, bool recommended, bool trustedPayment, bool trustlessPayment, bool ofacCompliant
    );

    /**
     * @notice Emitted when a builder is removed from the registry
     * @param builder The address of the removed builder
     */
    event BuilderRemoved(address indexed builder);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Transfers ownership of the contract to a new address
     * @dev Can only be called by the current owner
     * @param newOwner The address of the new owner
     */
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    /**
     * @notice Sets or updates builder information in the registry
     * @dev If the builder is new, it will be added to the builderList.
     *      If the builder already exists, its information will be updated.
     * @param builder The address of the builder
     * @param info The builder metadata to set
     */
    function setBuilder(address builder, BuilderInfo calldata info) external onlyOwner {
        require(builder != address(0), "zero builder");

        BuilderInfo storage stored = builders[builder];

        // if new, add to list (builderIndex[builder] == 0 means not in list)
        if (builderIndex[builder] == 0) {
            builderList.push(builder);
            builderIndex[builder] = builderList.length; // Store index + 1
        }

        stored.recommended = info.recommended;
        stored.trustedPayment = info.trustedPayment;
        stored.trustlessPayment = info.trustlessPayment;
        stored.ofacCompliant = info.ofacCompliant;

        emit BuilderSet(builder, info.recommended, info.trustedPayment, info.trustlessPayment, info.ofacCompliant);
    }

    /**
     * @notice Removes a builder from the registry
     * @dev Uses swap-and-pop for efficient array removal. The builder is
     *      completely removed from both the mapping and the list.
     * @param builder The address of the builder to remove
     */
    function removeBuilder(address builder) external onlyOwner {
        uint256 indexPlusOne = builderIndex[builder];
        require(indexPlusOne > 0, "builder not found");

        uint256 index = indexPlusOne - 1;
        uint256 lastIndex = builderList.length - 1;

        if (index != lastIndex) {
            address lastBuilder = builderList[lastIndex];
            builderList[index] = lastBuilder;
            // upd moved builders index
            builderIndex[lastBuilder] = indexPlusOne;
        }

        // del last element
        builderList.pop();
        delete builderIndex[builder];
        delete builders[builder];

        emit BuilderRemoved(builder);
    }

    /**
     * @notice Returns all registered builders in the registry
     * @return Array of all builder addresses
     */
    function getAllBuilders() external view returns (address[] memory) {
        return builderList;
    }

    /**
     * @notice Check if a builder is registered in the system
     * @param builder The address to check
     * @return True if the builder is registered
     */
    function isBuilderRegistered(address builder) external view returns (bool) {
        return builderIndex[builder] > 0;
    }

    /**
     * @notice Get builders that match the specified filter criteria
     * @dev Compares builder state directly with the requested values.
     *      Only fields where `filterMask` bit is set are checked.
     *      Bit positions: 0=recommended, 1=trustedPayment, 2=trustlessPayment, 3=ofacCompliant
     *      Example: To get recommended builders that are NOT OFAC compliant:
     *      - filterMask = 1001 (bits 0 and 3 set = check recommended and ofacCompliant)
     *      - filter = BuilderInfo({recommended: true, ofacCompliant: false, ...})
     * @param filter The exact state values to match against
     * @param filterMask Bitmask indicating which fields to check (bit 0=recommended, 1=trustedPayment, 2=trustlessPayment, 3=ofacCompliant)
     * @return Array of builder addresses matching all specified filter criteria
     */
    function getBuildersByFilter(BuilderInfo calldata filter, uint8 filterMask)
        external
        view
        returns (address[] memory)
    {
        uint256 len = builderList.length;
        address[] memory result = new address[](len);
        uint256 idx;

        for (uint256 i = 0; i < len; i++) {
            if (_matchesFilter(builderList[i], filter, filterMask)) {
                result[idx++] = builderList[i];
            }
        }

        // Resize array to actual count
        assembly {
            mstore(result, idx)
        }
        return result;
    }

    /**
     * @notice Internal function to check if a builder matches the filter criteria
     * @param builder The builder address to check
     * @param filter The exact state values to match against
     * @param filterMask Bitmask indicating which fields to check
     * @return True if the builder matches all specified filter criteria
     */
    function _matchesFilter(address builder, BuilderInfo calldata filter, uint8 filterMask)
        internal
        view
        returns (bool)
    {
        BuilderInfo storage info = builders[builder];

        // check each field if the corresponding bit is set in filterMask
        if ((filterMask & 0x01) != 0 && info.recommended != filter.recommended) {
            return false;
        }
        if ((filterMask & 0x02) != 0 && info.trustedPayment != filter.trustedPayment) return false;
        if ((filterMask & 0x04) != 0 && info.trustlessPayment != filter.trustlessPayment) return false;
        if ((filterMask & 0x08) != 0 && info.ofacCompliant != filter.ofacCompliant) {
            return false;
        }

        return true;
    }
}
