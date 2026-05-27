// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderRecord, IBuilderList} from "./interfaces/IERC8218.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";

/// @title PermissionedBuilderRegistry
/// @notice Permissioned counterpart to `OpenBuilderRegistry` where the contract
/// owner curates a single builder list instead of builders self-registering
/// with BLS signatures.
contract PermissionedBuilderRegistry is Ownable, IBuilderList {
    /// @notice Maximum FQDN length in bytes (RFC 1035 §2.3.4).
    uint256 public constant MAX_FQDN_LENGTH = 253;

    /// @notice Ordered list of builder records.
    BuilderRecord[] internal _builders;

    /// @notice Pubkey hash to 1-based index in `_builders` (0 means not registered).
    mapping(bytes32 => uint256) internal _indexByPubkeyHash;

    event BuilderRegistered(bytes pubkey, string fqdn);
    event BuilderDeregistered(bytes pubkey);

    error InvalidPubkeyLength(uint256 length);
    error EmptyFQDN();
    error FQDNTooLong(uint256 length);
    error NotRegistered();
    error IndexOutOfBounds();

    constructor() Ownable(msg.sender) {}

    function setOwner(address newOwner) external onlyOwner {
        transferOwnership(newOwner);
    }

    /// @notice Register a new builder or update an existing builder's FQDN.
    /// @dev Permissioned variant of ERC-8218 registration: the contract owner writes the
    /// builder record directly instead of verifying a BLS signature from the builder.
    function registerBuilder(bytes calldata pubkey, string calldata fqdn) external onlyOwner {
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

        emit BuilderRegistered(pubkey, fqdn);
    }

    /// @notice Deregister a previously listed builder.
    function deregisterBuilder(bytes calldata pubkey) external onlyOwner {
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

        emit BuilderDeregistered(pubkey);
    }

    /// @notice Check whether a builder pubkey is currently listed.
    function isBuilderRegistered(bytes calldata pubkey) external view returns (bool) {
        return _indexByPubkeyHash[keccak256(pubkey)] != 0;
    }

    function builderCount() external view returns (uint256) {
        return _builders.length;
    }

    function getBuilderAtIndex(uint256 index) external view returns (BuilderRecord memory) {
        if (index >= _builders.length) revert IndexOutOfBounds();
        return _builders[index];
    }
}
