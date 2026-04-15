// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderRecord, IBuilderRegistry, IBuilderList} from "./interfaces/IERC8218.sol";
import {BLS12381} from "./lib/BLS12381.sol";

/// @title PermissionlessRegistry
/// @notice ERC-8218 permissionless builder registry with BLS12-381 signature
/// verification via EIP-2537 precompiles.
contract PermissionlessRegistry is IBuilderRegistry, IBuilderList {
    /// @notice Ordered list of builder records.
    BuilderRecord[] internal _builders;

    /// @notice Pubkey hash to 1-based index in `_builders` (0 means not registered).
    mapping(bytes32 => uint256) internal _indexByPubkeyHash;

    /// @notice Pubkey hash to nonce to used flag.
    mapping(bytes32 => mapping(bytes32 => bool)) internal _usedNonces;

    /// @dev Thrown when the pubkey is not exactly 48 bytes.
    error InvalidPubkeyLength(uint256 length);
    /// @dev Thrown when the FQDN is empty.
    error EmptyFQDN();
    /// @dev Thrown when a nonce has already been consumed for a given pubkey.
    error NonceAlreadyUsed();
    /// @dev Thrown when the signature is not 192 or 256 bytes.
    error InvalidSignatureLength(uint256 length);
    /// @dev Thrown when the BLS pairing check fails.
    error SignatureVerificationFailed();
    /// @dev Thrown when the requested builder index is out of range.
    error IndexOutOfBounds();

    /// @inheritdoc IBuilderRegistry
    function registerBuilder(bytes calldata pubkey, string calldata fqdn, bytes32 nonce, bytes calldata signature)
        external
    {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);
        if (bytes(fqdn).length == 0) revert EmptyFQDN();
        if (signature.length != 192 && signature.length != 256) revert InvalidSignatureLength(signature.length);

        bytes32 pkHash = keccak256(pubkey);

        if (_usedNonces[pkHash][nonce]) revert NonceAlreadyUsed();
        _usedNonces[pkHash][nonce] = true;

        // Verify BLS signature
        bytes memory message = abi.encode(block.chainid, address(this), pubkey, fqdn, nonce);
        if (!BLS12381.verifySignature(pubkey, message, signature)) {
            revert SignatureVerificationFailed();
        }

        // Add or update
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) {
            _builders.push(BuilderRecord({pubkey: pubkey, fqdn: fqdn}));
            _indexByPubkeyHash[pkHash] = _builders.length;
        } else {
            _builders[idx - 1].fqdn = fqdn;
        }

        emit BuilderRegistered(pubkey, fqdn, nonce);
    }

    /// @inheritdoc IBuilderList
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
