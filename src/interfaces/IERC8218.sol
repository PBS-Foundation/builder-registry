// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

struct BuilderRecord {
    bytes pubkey; // 48 bytes, BLS12-381 compressed G1 point
    string fqdn;
}

interface IBuilderRegistry {
    event BuilderRegistered(bytes pubkey, string fqdn, bytes32 nonce);

    function registerBuilder(
        bytes calldata pubkey,
        string calldata fqdn,
        bytes32 nonce,
        bytes calldata signature
    ) external;
}

interface IBuilderList {
    function builderCount(uint256 listId) external view returns (uint256);

    function getBuilderAtIndex(uint256 listId, uint256 index) external view returns (BuilderRecord memory);
}
