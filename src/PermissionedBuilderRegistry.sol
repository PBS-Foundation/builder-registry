// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderRecord, IBuilderList} from "./interfaces/IERC8218.sol";

/// @title PermissionedBuilderRegistry
/// @notice Permissioned counterpart to `OpenBuilderRegistry`.
/// Builders are listed through owner-approved curators instead of self-registering
/// with BLS signatures.
contract PermissionedBuilderRegistry is IBuilderList {
    /// @notice Maximum FQDN length in bytes (RFC 1035 §2.3.4).
    uint256 public constant MAX_FQDN_LENGTH = 253;

    /// @notice Contract owner, expected to be a multisig or governance address.
    address public owner;

    /// @notice Curators that are allowed to manage the builder list.
    mapping(address => bool) public curators;

    /// @notice Ordered list of builder records.
    BuilderRecord[] internal _builders;

    /// @notice Pubkey hash to 1-based index in `_builders` (0 means not registered).
    mapping(bytes32 => uint256) internal _indexByPubkeyHash;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event CuratorRegistered(address indexed curator);
    event CuratorUnregistered(address indexed curator);
    event BuilderRegistered(bytes pubkey, string fqdn, address indexed curator);
    event BuilderDeregistered(bytes pubkey, address indexed curator);

    error NotOwner();
    error NotCurator();
    error ZeroAddress();
    error InvalidPubkeyLength(uint256 length);
    error EmptyFQDN();
    error FQDNTooLong(uint256 length);
    error AlreadyCurator();
    error NotRegistered();
    error IndexOutOfBounds();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyCurator() {
        if (!curators[msg.sender]) revert NotCurator();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnerChanged(address(0), msg.sender);
    }

    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function registerCurator(address curator) external onlyOwner {
        if (curator == address(0)) revert ZeroAddress();
        if (curators[curator]) revert AlreadyCurator();
        curators[curator] = true;
        emit CuratorRegistered(curator);
    }

    function unregisterCurator(address curator) external onlyOwner {
        if (!curators[curator]) revert NotCurator();
        delete curators[curator];
        emit CuratorUnregistered(curator);
    }

    /// @notice Register a new builder or update an existing builder's FQDN.
    /// @dev Permissioned variant of ERC-8218 registration: a curator writes the
    /// builder record directly instead of verifying a BLS signature from the builder.
    function registerBuilder(bytes calldata pubkey, string calldata fqdn) external onlyCurator {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);
        uint256 fqdnLen = bytes(fqdn).length;
        if (fqdnLen == 0) revert EmptyFQDN();
        if (fqdnLen > MAX_FQDN_LENGTH) revert FQDNTooLong(fqdnLen);

        bytes32 pkHash = keccak256(pubkey);
        uint256 idx = _indexByPubkeyHash[pkHash];

        if (idx == 0) {
            _builders.push(BuilderRecord({pubkey: pubkey, fqdn: fqdn}));
            _indexByPubkeyHash[pkHash] = _builders.length;
        } else {
            _builders[idx - 1].fqdn = fqdn;
        }

        emit BuilderRegistered(pubkey, fqdn, msg.sender);
    }

    /// @notice Deregister a previously listed builder.
    function deregisterBuilder(bytes calldata pubkey) external onlyCurator {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);

        bytes32 pkHash = keccak256(pubkey);
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) revert NotRegistered();

        uint256 lastIdx = _builders.length;
        if (idx != lastIdx) {
            BuilderRecord storage last = _builders[lastIdx - 1];
            _builders[idx - 1] = last;
            _indexByPubkeyHash[keccak256(last.pubkey)] = idx;
        }
        _builders.pop();
        delete _indexByPubkeyHash[pkHash];

        emit BuilderDeregistered(pubkey, msg.sender);
    }

    /// @notice Check whether a builder pubkey is currently listed.
    function isBuilderRegistered(bytes calldata pubkey) external view returns (bool) {
        return _indexByPubkeyHash[keccak256(pubkey)] != 0;
    }

    /// @inheritdoc IBuilderList
    /// @dev `listId` is ignored because this contract exposes a single global list.
    function builderCount(
        uint256 /* listId */
    )
        external
        view
        returns (uint256)
    {
        return _builders.length;
    }

    /// @inheritdoc IBuilderList
    /// @dev `listId` is ignored because this contract exposes a single global list.
    function getBuilderAtIndex(
        uint256,
        /* listId */
        uint256 index
    )
        external
        view
        returns (BuilderRecord memory)
    {
        if (index >= _builders.length) revert IndexOutOfBounds();
        return _builders[index];
    }
}
