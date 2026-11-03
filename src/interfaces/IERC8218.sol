// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

/// @notice A single builder entry: the builder's BLS pubkey and how to reach its Builder-API.
/// @param pubkey 48-byte BLS12-381 compressed G1 point identifying the builder. This is the
/// same key as `state.builders[i].pubkey` in the Gloas beacon state.
/// @param url Base URL of the builder's Builder-API, e.g. `https://builder.example.com:18550`.
/// Clients append the Builder-API paths (e.g. `/eth/v1/builder/execution_payload_bid/...`)
/// after stripping any trailing `/`. The URL carries no userinfo, query or fragment.
/// @param authData The `BuilderRequestAuth.data` value the builder expects proposers to sign.
/// Empty means the builder-specs default: the hostname of `url`.
/// @param updatedAt Timestamp of the block in which this record was last written.
struct BuilderRecord {
    bytes pubkey;
    string url;
    bytes authData;
    uint64 updatedAt;
}

/// @title IBuilderRegistry
/// @notice ERC-8218 interface for permissionlessly registering and deregistering
/// builders via BLS signatures over request data.
interface IBuilderRegistry {
    /// @notice Register a new builder or update an existing builder's record.
    /// @dev Reverts if the signature does not verify under `pubkey` over
    /// `abi.encode(block.chainid, address(this), pubkey, url, authData, nonce)`, or if
    /// `nonce` is not strictly greater than `nonces(pubkey)`.
    /// @param pubkey 48-byte BLS12-381 compressed G1 pubkey.
    /// @param url Base URL of the builder's Builder-API.
    /// @param authData Expected `BuilderRequestAuth.data`; empty for the default.
    /// @param nonce Per-pubkey nonce; must exceed the last consumed nonce.
    /// @param signature BLS12-381 signature (G2 point) over the request.
    function registerBuilder(
        bytes calldata pubkey,
        string calldata url,
        bytes calldata authData,
        uint64 nonce,
        bytes calldata signature
    ) external;

    /// @notice Deregister a previously registered builder.
    /// @dev Reverts if `pubkey` is not currently registered, the signature does
    /// not verify over `abi.encode(block.chainid, address(this), pubkey, nonce)`,
    /// or `nonce` is not strictly greater than `nonces(pubkey)`.
    /// @param pubkey 48-byte BLS12-381 compressed G1 pubkey.
    /// @param nonce Per-pubkey nonce; must exceed the last consumed nonce.
    /// @param signature BLS12-381 signature (G2 point) over the request.
    function deregisterBuilder(bytes calldata pubkey, uint64 nonce, bytes calldata signature) external;

    /// @notice The last nonce consumed for `pubkey` (0 if none). The next signed
    /// request must use a strictly greater nonce.
    function nonces(bytes calldata pubkey) external view returns (uint64);
}

/// @title IBuilderList
/// @notice ERC-8218 read interface for enumerating and looking up builders.
/// @dev Every list emits the same events so clients can sync any registry from logs
/// with a single code path.
interface IBuilderList {
    /// @notice Emitted when a builder is added or its record is updated.
    /// @param pubkeyHash `keccak256(pubkey)`, indexed for filtering.
    event BuilderRegistered(bytes32 indexed pubkeyHash, bytes pubkey, string url, bytes authData);

    /// @notice Emitted when a builder is removed from the list.
    /// @param pubkeyHash `keccak256(pubkey)`, indexed for filtering.
    event BuilderDeregistered(bytes32 indexed pubkeyHash, bytes pubkey);

    /// @notice Total number of builders in the list.
    function builderCount() external view returns (uint256);

    /// @notice Return the builder at `index` in the list.
    /// @dev Reverts when `index >= builderCount()`. Indexes are enumeration positions,
    /// not stable identifiers: removal may move another record to a different index.
    function getBuilderAtIndex(uint256 index) external view returns (BuilderRecord memory);

    /// @notice Return up to `limit` records starting at `offset`.
    /// @dev Returns an empty array when `offset >= builderCount()`.
    function getBuilders(uint256 offset, uint256 limit) external view returns (BuilderRecord[] memory);

    /// @notice Return the record for `pubkey`.
    /// @dev Reverts when `pubkey` is not in the list.
    function getBuilder(bytes calldata pubkey) external view returns (BuilderRecord memory);

    /// @notice Whether `pubkey` is currently in the list.
    function isBuilderRegistered(bytes calldata pubkey) external view returns (bool);
}
