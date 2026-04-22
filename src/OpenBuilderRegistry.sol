// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderRecord, IBuilderRegistry, IBuilderList} from "./interfaces/IERC8218.sol";
import {BLS12381} from "./lib/BLS12381.sol";

/// @title OpenBuilderRegistry
/// @notice ERC-8218 open builder registry implementation with BLS12-381 signature
/// verification via EIP-2537 precompiles.
contract OpenBuilderRegistry is IBuilderRegistry, IBuilderList {
    /// @notice Maximum FQDN length in bytes (RFC 1035 §2.3.4).
    uint256 public constant MAX_FQDN_LENGTH = 253;

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
    /// @dev Thrown when the FQDN exceeds `MAX_FQDN_LENGTH` bytes.
    error FQDNTooLong(uint256 length);
    /// @dev Thrown when a nonce has already been consumed for a given pubkey.
    error NonceAlreadyUsed();
    /// @dev Thrown when the signature is not 192 or 256 bytes.
    error InvalidSignatureLength(uint256 length);
    /// @dev Thrown when the BLS pairing check fails.
    error SignatureVerificationFailed();
    /// @dev Thrown when the builder is not registered.
    error NotRegistered();
    /// @dev Thrown when the requested builder index is out of range.
    error IndexOutOfBounds();

    /// @inheritdoc IBuilderRegistry
    /// @dev A re-registration (same pubkey, new fqdn) overwrites the stored FQDN
    /// and emits `BuilderRegistered` — there is no separate update event.
    function registerBuilder(bytes calldata pubkey, string calldata fqdn, bytes32 nonce, bytes calldata signature)
        external
    {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);
        uint256 fqdnLen = bytes(fqdn).length;
        if (fqdnLen == 0) revert EmptyFQDN();
        if (fqdnLen > MAX_FQDN_LENGTH) revert FQDNTooLong(fqdnLen);
        if (signature.length != 192 && signature.length != 256) revert InvalidSignatureLength(signature.length);

        bytes32 pkHash = keccak256(pubkey);

        if (_usedNonces[pkHash][nonce]) revert NonceAlreadyUsed();
        _usedNonces[pkHash][nonce] = true;

        // Verify BLS signature
        bytes memory message = abi.encode(block.chainid, address(this), pubkey, fqdn, nonce);
        if (!BLS12381.verifySignature(pubkey, message, signature)) {
            revert SignatureVerificationFailed();
        }

        // Add or update. Update path reuses BuilderRegistered rather than emitting
        // a distinct event — consumers should treat BuilderRegistered as an upsert.
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) {
            _builders.push(BuilderRecord({pubkey: pubkey, fqdn: fqdn}));
            _indexByPubkeyHash[pkHash] = _builders.length;
        } else {
            _builders[idx - 1].fqdn = fqdn;
        }

        emit BuilderRegistered(pubkey, fqdn, nonce);
    }

    /// @inheritdoc IBuilderRegistry
    function deregisterBuilder(bytes calldata pubkey, bytes32 nonce, bytes calldata signature) external {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);
        if (signature.length != 192 && signature.length != 256) revert InvalidSignatureLength(signature.length);

        bytes32 pkHash = keccak256(pubkey);

        // Check registration before BLS verify so unregistered-pubkey calls fail cheaply.
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) revert NotRegistered();

        if (_usedNonces[pkHash][nonce]) revert NonceAlreadyUsed();
        _usedNonces[pkHash][nonce] = true;

        // Verify BLS signature (message excludes fqdn per ERC-8218)
        bytes memory message = abi.encode(block.chainid, address(this), pubkey, nonce);
        if (!BLS12381.verifySignature(pubkey, message, signature)) {
            revert SignatureVerificationFailed();
        }

        // Swap-and-pop removal to avoid gaps
        uint256 lastIdx = _builders.length;
        if (idx != lastIdx) {
            BuilderRecord storage last = _builders[lastIdx - 1];
            _builders[idx - 1] = last;
            _indexByPubkeyHash[keccak256(last.pubkey)] = idx;
        }
        _builders.pop();
        delete _indexByPubkeyHash[pkHash];

        emit BuilderDeregistered(pubkey, nonce);
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
