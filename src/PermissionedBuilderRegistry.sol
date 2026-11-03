// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderListBase} from "./BuilderListBase.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {
    Ownable2Step
} from "openzeppelin-contracts/contracts/access/Ownable2Step.sol";

/// @title PermissionedBuilderRegistry
/// @notice Permissioned counterpart to `OpenBuilderRegistry` where the contract
/// owner curates a single builder list instead of builders self-registering
/// with BLS signatures.
/// @dev The owner's write does not prove that the builder controls `pubkey` or `url`;
/// clients must still perform the builder handshake before trusting an entry.
/// Ownership transfers are two-step (`transferOwnership` + `acceptOwnership`).
contract PermissionedBuilderRegistry is Ownable2Step, BuilderListBase {
    constructor() Ownable(msg.sender) {}

    /// @notice Register a new builder or update an existing builder's record.
    /// @param pubkey 48-byte BLS12-381 compressed G1 pubkey.
    /// @param url Base URL of the builder's Builder-API.
    /// @param authData Expected `BuilderRequestAuth.data`; empty for the default.
    function registerBuilder(
        bytes calldata pubkey,
        string calldata url,
        bytes calldata authData
    ) external onlyOwner {
        _validatePubkey(pubkey);
        _validateEndpoint(url, authData);
        _upsert(keccak256(pubkey), pubkey, url, authData);
    }

    /// @notice Deregister a previously listed builder.
    function deregisterBuilder(bytes calldata pubkey) external onlyOwner {
        bytes32 pkHash = keccak256(pubkey);
        _remove(pkHash, _requireIndex(pkHash), pubkey);
    }
}
