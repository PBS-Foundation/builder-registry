// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBuilderRegistry} from "./interfaces/IERC8218.sol";
import {BuilderListBase} from "./BuilderListBase.sol";
import {BLS12381} from "./lib/BLS12381.sol";

/// @title OpenBuilderRegistry
/// @notice ERC-8218 open builder registry implementation with BLS12-381 signature
/// verification via EIP-2537 precompiles.
contract OpenBuilderRegistry is IBuilderRegistry, BuilderListBase {
    /// @dev Pubkey hash to the last consumed nonce. Kept across deregistration so an
    /// old signed registration cannot be replayed after the builder leaves.
    mapping(bytes32 => uint64) internal _nonces;

    /// @dev Thrown when `nonce` is not strictly greater than the last consumed nonce.
    error StaleNonce(uint64 nonce, uint64 lastNonce);
    /// @dev Thrown when the signature is not 192 or 256 bytes.
    error InvalidSignatureLength(uint256 length);
    /// @dev Thrown when the BLS pairing check fails.
    error SignatureVerificationFailed();

    /// @inheritdoc IBuilderRegistry
    /// @dev A re-registration (same pubkey, higher nonce) overwrites the stored record
    /// and emits `BuilderRegistered` — consumers should treat it as an upsert.
    function registerBuilder(
        bytes calldata pubkey,
        string calldata url,
        bytes calldata authData,
        uint64 nonce,
        bytes calldata signature
    ) external {
        _validatePubkey(pubkey);
        _validateEndpoint(url, authData);
        _validateSignatureLength(signature);

        bytes32 pkHash = keccak256(pubkey);
        _consumeNonce(pkHash, nonce);

        bytes memory message = abi.encode(
            block.chainid,
            address(this),
            pubkey,
            url,
            authData,
            nonce
        );
        if (!BLS12381.verifySignature(pubkey, message, signature))
            revert SignatureVerificationFailed();

        _upsert(pkHash, pubkey, url, authData);
    }

    /// @inheritdoc IBuilderRegistry
    function deregisterBuilder(
        bytes calldata pubkey,
        uint64 nonce,
        bytes calldata signature
    ) external {
        _validatePubkey(pubkey);
        _validateSignatureLength(signature);

        bytes32 pkHash = keccak256(pubkey);
        // Check registration before BLS verify so unregistered-pubkey calls fail cheaply.
        uint256 idx = _requireIndex(pkHash);
        _consumeNonce(pkHash, nonce);

        bytes memory message = abi.encode(
            block.chainid,
            address(this),
            pubkey,
            nonce
        );
        if (!BLS12381.verifySignature(pubkey, message, signature))
            revert SignatureVerificationFailed();

        _remove(pkHash, idx, pubkey);
    }

    /// @inheritdoc IBuilderRegistry
    function nonces(bytes calldata pubkey) external view returns (uint64) {
        return _nonces[keccak256(pubkey)];
    }

    /// @dev Require `nonce` to be strictly increasing per pubkey, so a signed request
    /// that lands late cannot roll the record back to an older state.
    function _consumeNonce(bytes32 pkHash, uint64 nonce) private {
        uint64 last = _nonces[pkHash];
        if (nonce <= last) revert StaleNonce(nonce, last);
        _nonces[pkHash] = nonce;
    }

    function _validateSignatureLength(bytes calldata signature) private pure {
        if (signature.length != 192 && signature.length != 256)
            revert InvalidSignatureLength(signature.length);
    }
}
