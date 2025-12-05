// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BuilderRegistry
 * @notice On-chain registry for builders in EPBS with curator management.
 */
contract BuilderRegistry {
    /// @notice The owner of the contract, typically a multisig Safe
    address public owner;

    struct Curator {
        bool exists;
        string metadataURI; // optional description / policy / website
    }

    mapping(address => Curator) public curators;

    /**
     * @notice Metadata structure for a builder
     * @param active Whether the builder is currently active
     * @param recommended Whether the builder is recommended for use
     * @param trustedPayment Whether the builder supports trusted payments
     * @param trustlessPayment Whether the builder supports trustless payments
     * @param ofacCompliant Whether the builder is OFAC compliant
     * @param blobSupport Whether the builder supports blobs
     */
    struct BuilderInfo {
        bool active;
        bool recommended;
        bool trustedPayment;
        bool trustlessPayment;
        bool ofacCompliant;
        bool blobSupport;
    }

    /// @notice Mapping from curator to builder to their metadata
    mapping(address => mapping(address => BuilderInfo)) public buildersByCurator;

    /// @notice Mapping from curator to list of builder addresses for iteration
    mapping(address => address[]) public builderListByCurator;

    /// @notice Mapping from curator to builder to their index in builderListByCurator + 1
    /// @dev We store index + 1 so that 0 means "not in list"
    mapping(address => mapping(address => uint256)) private builderIndexByCurator;

    /**
     * @notice Emitted when the contract owner is changed
     * @param oldOwner The previous owner address
     * @param newOwner The new owner address
     */
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    /**
     * @notice Emitted when a curator is registered
     * @param curator The address of the curator
     * @param metadataURI The metadata URI for the curator
     */
    event CuratorRegistered(address indexed curator, string metadataURI);

    /**
     * @notice Emitted when a curator's metadata is updated
     * @param curator The address of the curator
     * @param metadataURI The updated metadata URI for the curator
     */
    event CuratorUpdated(address indexed curator, string metadataURI);

    /**
     * @notice Emitted when a curator is unregistered
     * @param curator The address of the unregistered curator
     */
    event CuratorUnregistered(address indexed curator);

    /**
     * @notice Emitted when a builder's information is set or updated
     * @param curator The address of the curator managing this builder
     * @param builder The address of the builder
     * @param active Whether the builder is active
     * @param recommended Whether the builder is recommended
     * @param trustedPayment Whether the builder supports trusted payments
     * @param trustlessPayment Whether the builder supports trustless payments
     * @param ofacCompliant Whether the builder is OFAC compliant
     * @param blobSupport Whether the builder supports blob transactions
     */
    event BuilderSet(
        address indexed curator,
        address indexed builder,
        bool active,
        bool recommended,
        bool trustedPayment,
        bool trustlessPayment,
        bool ofacCompliant,
        bool blobSupport
    );

    /**
     * @notice Emitted when a builder is removed from the registry
     * @param curator The address of the curator managing this builder
     * @param builder The address of the removed builder
     */
    event BuilderRemoved(address indexed curator, address indexed builder);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyCurator() {
        require(curators[msg.sender].exists, "not curator");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnerChanged(address(0), msg.sender);
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
     * @notice Registers a new curator in the registry
     * @dev Can only be called by the owner
     * @param curator The address of the curator to register
     * @param metadataURI The metadata URI for the curator
     */
    function registerCurator(address curator, string calldata metadataURI) external onlyOwner {
        require(curator != address(0), "zero address");
        require(!curators[curator].exists, "already curator");
        curators[curator] = Curator({exists: true, metadataURI: metadataURI});
        emit CuratorRegistered(curator, metadataURI);
    }

    /**
     * @notice Updates the metadata URI for an existing curator
     * @dev Can only be called by the owner
     * @param curator The address of the curator
     * @param metadataURI The new metadata URI
     */
    function updateCuratorMetadata(address curator, string calldata metadataURI) external onlyOwner {
        require(curators[curator].exists, "not curator");
        curators[curator].metadataURI = metadataURI;
        emit CuratorUpdated(curator, metadataURI);
    }

    /**
     * @notice Unregisters a curator from the registry
     * @dev Can only be called by the owner. Note: we do NOT clean builderListByCurator/buildersByCurator
     *      to avoid gas grief; consumers should simply ignore non-curators.
     * @param curator The address of the curator to unregister
     */
    function unregisterCurator(address curator) external onlyOwner {
        require(curators[curator].exists, "not curator");
        delete curators[curator];
        emit CuratorUnregistered(curator);
    }

    // --- Curator functions ---

    /**
     * @notice Sets or updates builder information in the registry
     * @dev If the builder is new, it will be added to the builderListByCurator.
     *      If the builder already exists, its information will be updated.
     *      Can only be called by a registered curator.
     * @param builder The address of the builder
     * @param info The builder metadata to set
     */
    function setBuilder(address builder, BuilderInfo calldata info) external onlyCurator {
        require(builder != address(0), "zero builder");

        BuilderInfo storage stored = buildersByCurator[msg.sender][builder];

        // if new add to list (builderIndexByCurator[msg.sender][builder] == 0 means not in list)
        if (builderIndexByCurator[msg.sender][builder] == 0) {
            builderListByCurator[msg.sender].push(builder);
            // store index + 1
            builderIndexByCurator[msg.sender][builder] = builderListByCurator[msg.sender].length;
        }

        stored.active = info.active;
        stored.recommended = info.recommended;
        stored.trustedPayment = info.trustedPayment;
        stored.trustlessPayment = info.trustlessPayment;
        stored.ofacCompliant = info.ofacCompliant;
        stored.blobSupport = info.blobSupport;

        emit BuilderSet(
            msg.sender,
            builder,
            info.active,
            info.recommended,
            info.trustedPayment,
            info.trustlessPayment,
            info.ofacCompliant,
            info.blobSupport
        );
    }

    /**
     * @notice Removes a builder from the registry
     * @dev swap and pop for efficient array removal. The builder is
     *      completely removed from both the mapping and the list.
     *      Can only be called by a registered curator.
     * @param builder The address of the builder to remove
     */
    function removeBuilder(address builder) external onlyCurator {
        uint256 indexPlusOne = builderIndexByCurator[msg.sender][builder];
        require(indexPlusOne > 0, "builder not found");

        uint256 index = indexPlusOne - 1;
        address[] storage list = builderListByCurator[msg.sender];
        uint256 lastIndex = list.length - 1;

        if (index != lastIndex) {
            address lastBuilder = list[lastIndex];
            list[index] = lastBuilder;
            // update moved builder's index
            builderIndexByCurator[msg.sender][lastBuilder] = indexPlusOne;
        }

        // delete last element
        list.pop();
        delete builderIndexByCurator[msg.sender][builder];
        delete buildersByCurator[msg.sender][builder];

        emit BuilderRemoved(msg.sender, builder);
    }

    // --- View functions for proposers / clients ---

    /**
     * @notice Returns all registered builders for a given curator
     * @param curator The address of the curator
     * @return Array of all builder addresses for the curator
     */
    function getAllBuilders(address curator) external view returns (address[] memory) {
        return builderListByCurator[curator];
    }

    /**
     * @notice Check if a builder is registered for a given curator
     * @param curator The address of the curator
     * @param builder The address to check
     * @return True if the builder is registered
     */
    function isBuilderRegistered(address curator, address builder) external view returns (bool) {
        return builderIndexByCurator[curator][builder] > 0;
    }

    /**
     * @notice Get builders that match the specified filter criteria
     * @dev Compares builder state directly with the requested values.
     *      Only fields where `filterMask` bit is set are checked.
     *      Bit positions: 0=active, 1=recommended, 2=trustedPayment, 3=trustlessPayment, 4=ofacCompliant, 5=blobSupport
     *      Example: To get recommended builders that are NOT OFAC compliant:
     *      - filterMask = 010010 (bits 1 and 4 set = check recommended and ofacCompliant)
     *      - filter = BuilderInfo({recommended: true, ofacCompliant: false, ...})
     * @param curator The address of the curator
     * @param filter The exact state values to match against
     * @param filterMask Bitmask indicating which fields to check (bit 0=active, 1=recommended, 2=trustedPayment, 3=trustlessPayment, 4=ofacCompliant, 5=blobSupport)
     * @return Array of builder addresses matching all specified filter criteria
     */
    function getBuildersByFilter(address curator, BuilderInfo calldata filter, uint8 filterMask)
        external
        view
        returns (address[] memory)
    {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;
        address[] memory result = new address[](len);
        uint256 idx;

        for (uint256 i = 0; i < len; i++) {
            if (_matchesFilter(curator, list[i], filter, filterMask)) {
                result[idx++] = list[i];
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
     * @param curator The address of the curator
     * @param builder The builder address to check
     * @param filter The exact state values to match against
     * @param filterMask Bitmask indicating which fields to check
     * @return True if the builder matches all specified filter criteria
     */
    function _matchesFilter(address curator, address builder, BuilderInfo calldata filter, uint8 filterMask)
        internal
        view
        returns (bool)
    {
        BuilderInfo storage info = buildersByCurator[curator][builder];

        // check each field if the corresponding bit is set in filterMask
        if ((filterMask & 0x01) != 0 && info.active != filter.active) {
            return false;
        }
        if ((filterMask & 0x02) != 0 && info.recommended != filter.recommended) {
            return false;
        }
        if ((filterMask & 0x04) != 0 && info.trustedPayment != filter.trustedPayment) return false;
        if ((filterMask & 0x08) != 0 && info.trustlessPayment != filter.trustlessPayment) return false;
        if ((filterMask & 0x10) != 0 && info.ofacCompliant != filter.ofacCompliant) return false;
        if ((filterMask & 0x20) != 0 && info.blobSupport != filter.blobSupport) {
            return false;
        }

        return true;
    }
}
