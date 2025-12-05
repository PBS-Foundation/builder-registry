// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract BuilderRegistry {
    // --- Roles ---

    address public owner;

    struct Curator {
        bool exists;
        string metadataURI; // optional description / policy / website
    }

    mapping(address => Curator) public curators;

    // --- Builder data ---

    struct BuilderInfo {
        bool exists;
        bool active;
        bool recommended;
        bool trustedPayment;
        bool trustlessPayment;
        bool ofacCompliant;
        bool blobSupport;
    }

    // curator => builder => info
    mapping(address => mapping(address => BuilderInfo)) public buildersByCurator;

    // curator => list of builder addresses for iteration
    mapping(address => address[]) public builderListByCurator;

    // --- Events ---

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    event CuratorRegistered(address indexed curator, string metadataURI);
    event CuratorUnregistered(address indexed curator);

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

    event BuilderRemoved(address indexed curator, address indexed builder);

    // --- Modifiers ---

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

    // --- Owner functions ---

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero address");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function registerCurator(address curator, string calldata metadataURI) external onlyOwner {
        require(curator != address(0), "zero address");
        require(!curators[curator].exists, "already curator");
        curators[curator] = Curator({exists: true, metadataURI: metadataURI});
        emit CuratorRegistered(curator, metadataURI);
    }

    function updateCuratorMetadata(address curator, string calldata metadataURI) external onlyOwner {
        require(curators[curator].exists, "not curator");
        curators[curator].metadataURI = metadataURI;
        // could emit a CuratorRegistered event again or a separate one
        emit CuratorRegistered(curator, metadataURI);
    }

    function unregisterCurator(address curator) external onlyOwner {
        require(curators[curator].exists, "not curator");
        delete curators[curator];
        emit CuratorUnregistered(curator);
        // Note: we do NOT clean builderListByCurator/ buildersByCurator
        // to avoid gas grief; consumers should simply ignore non-curators.
    }

    // --- Curator functions ---

    struct BuilderInfoInput {
        bool active;
        bool recommended;
        bool trustedPayment;
        bool trustlessPayment;
        bool ofacCompliant;
        bool blobSupport; 
    }

    function setBuilder(address builder, BuilderInfoInput calldata info) external onlyCurator {
        require(builder != address(0), "zero builder");

        BuilderInfo storage stored = buildersByCurator[msg.sender][builder];

        // if new, add to list
        if (!stored.exists) {
            stored.exists = true;
            builderListByCurator[msg.sender].push(builder);
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

    function removeBuilder(address builder) external onlyCurator {
        BuilderInfo storage stored = buildersByCurator[msg.sender][builder];
        require(stored.exists, "builder not found");

        // soft delete: mark as non-existent & inactive
        stored.exists = false;
        stored.active = false;
        stored.recommended = false;
        stored.trustedPayment = false;
        stored.trustlessPayment = false;
        stored.ofacCompliant = false;
        stored.blobSupport = false;

        emit BuilderRemoved(msg.sender, builder);
        // We keep the address in builderListByCurator to avoid O(n) cleanup.
        // Consumers should check .exists.
    }

    // --- View functions for proposers / clients ---

    function getAllBuilders(address curator) external view returns (address[] memory) {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;

        // Filter out non-existing
        uint256 count;
        for (uint256 i = 0; i < len; i++) {
            if (buildersByCurator[curator][list[i]].exists) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < len; i++) {
            if (buildersByCurator[curator][list[i]].exists) {
                result[idx++] = list[i];
            }
        }
        return result;
    }

    function getActiveBuilders(address curator) external view returns (address[] memory) {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;

        uint256 count;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.active) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.active) {
                result[idx++] = list[i];
            }
        }
        return result;
    }

    
    function getBlobBuilders(address curator) external view returns (address[] memory) {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;

        uint256 count;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.active && info.blobSupport) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.active && info.blobSupport) {
                result[idx++] = list[i];
            }
        }

        return result;
        }


    function getRecommendedBuilders(address curator) external view returns (address[] memory) {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;

        uint256 count;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.recommended && info.active) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < len; i++) {
            BuilderInfo storage info = buildersByCurator[curator][list[i]];
            if (info.exists && info.recommended && info.active) {
                result[idx++] = list[i];
            }
        }
        return result;
    }

    function getBuildersByFilter(
        address curator,
        bool onlyTrustedPayment,
        bool onlyTrustlessPayment,
        bool onlyOFAC
    ) external view returns (address[] memory) {
        address[] storage list = builderListByCurator[curator];
        uint256 len = list.length;

        uint256 count;
        for (uint256 i = 0; i < len; i++) {
            if (_matchesFilter(curator, list[i], onlyTrustedPayment, onlyTrustlessPayment, onlyOFAC)) {
                count++;
            }
        }

        address[] memory result = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < len; i++) {
            if (_matchesFilter(curator, list[i], onlyTrustedPayment, onlyTrustlessPayment, onlyOFAC)) {
                result[idx++] = list[i];
            }
        }
        return result;
    }

    function _matchesFilter(
        address curator,
        address builder,
        bool onlyTrustedPayment,
        bool onlyTrustlessPayment,
        bool onlyOFAC
    ) internal view returns (bool) {
        BuilderInfo storage info = buildersByCurator[curator][builder];
        if (!info.exists || !info.active) return false;
        if (onlyTrustedPayment && !info.trustedPayment) return false;
        if (onlyTrustlessPayment && !info.trustlessPayment) return false;
        if (onlyOFAC && !info.ofacCompliant) return false;
        return true;
    }
}
