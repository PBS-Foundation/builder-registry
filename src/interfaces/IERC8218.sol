// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @notice A single builder entry: BLS pubkey and the FQDN where the builder is reachable.
/// @param pubkey 48-byte BLS12-381 compressed G1 point identifying the builder.
/// @param fqdn Fully qualified domain name where the builder accepts requests.
struct BuilderRecord {
    bytes pubkey;
    string fqdn;
}

/// @title IBuilderRegistry
/// @notice ERC-8218 interface for permissionlessly registering and deregistering
/// builders via BLS signatures over request data.
interface IBuilderRegistry {
    /// @notice Emitted when a builder is registered or its FQDN is updated.
    /// @param pubkey The builder's BLS12-381 pubkey (48 bytes compressed).
    /// @param fqdn The FQDN associated with the builder.
    /// @param nonce The nonce consumed by this registration.
    event BuilderRegistered(bytes pubkey, string fqdn, bytes32 nonce);

    /// @notice Emitted when a builder is deregistered.
    /// @param pubkey The deregistered builder's BLS12-381 pubkey.
    /// @param nonce The nonce consumed by this deregistration.
    event BuilderDeregistered(bytes pubkey, bytes32 nonce);

    /// @notice Register a new builder or update an existing builder's FQDN.
    /// @dev Reverts if the signature does not verify under `pubkey` over
    /// `abi.encode(block.chainid, address(this), pubkey, fqdn, nonce)`, or if
    /// `nonce` has already been consumed by this pubkey.
    /// @param pubkey 48-byte BLS12-381 compressed G1 pubkey.
    /// @param fqdn The FQDN to associate with the builder.
    /// @param nonce A pubkey-scoped nonce preventing replay.
    /// @param signature BLS12-381 signature (G2 point) over the request.
    function registerBuilder(bytes calldata pubkey, string calldata fqdn, bytes32 nonce, bytes calldata signature)
        external;

    /// @notice Deregister a previously registered builder.
    /// @dev Reverts if `pubkey` is not currently registered, the signature does
    /// not verify over `abi.encode(block.chainid, address(this), pubkey, nonce)`,
    /// or `nonce` has already been consumed by this pubkey.
    /// @param pubkey 48-byte BLS12-381 compressed G1 pubkey.
    /// @param nonce A pubkey-scoped nonce preventing replay.
    /// @param signature BLS12-381 signature (G2 point) over the request.
    function deregisterBuilder(bytes calldata pubkey, bytes32 nonce, bytes calldata signature) external;
}

/// @title IBuilderList
/// @notice ERC-8218 read interface for enumerating registered builders.
interface IBuilderList {
    /// @notice Total number of builders in the given list.
    /// @param listId Reserved for implementations that expose multiple lists.
    /// @return The number of builders currently registered.
    function builderCount(uint256 listId) external view returns (uint256);

    /// @notice Return the builder at `index` in the given list.
    /// @dev Reverts when `index >= builderCount(listId)`.
    /// @param listId Reserved for implementations that expose multiple lists.
    /// @param index Zero-based index into the list.
    /// @return The builder record at that position.
    function getBuilderAtIndex(uint256 listId, uint256 index) external view returns (BuilderRecord memory);
}
