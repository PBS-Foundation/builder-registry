// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BuilderRecord, IBuilderList} from "./interfaces/IERC8218.sol";

/// @title BuilderListBase
/// @notice Shared storage, input validation and `IBuilderList` views for ERC-8218 registries.
/// Admission logic (BLS-authorized or owner-curated) lives in the inheriting contract.
abstract contract BuilderListBase is IBuilderList {
    /// @notice Maximum URL length in bytes.
    uint256 public constant MAX_URL_LENGTH = 512;

    /// @notice Maximum `authData` length, matching builder-specs `MAX_BUILDER_AUTH_DATA_SIZE`.
    uint256 public constant MAX_AUTH_DATA_LENGTH = 4096;

    /// @dev Ordered list of builder records.
    BuilderRecord[] internal _builders;

    /// @dev Pubkey hash to 1-based index in `_builders` (0 means not registered).
    mapping(bytes32 => uint256) internal _indexByPubkeyHash;

    /// @dev Pubkey is not exactly 48 bytes.
    error InvalidPubkeyLength(uint256 length);
    /// @dev Pubkey lacks the compression flag or is the point at infinity.
    error InvalidPubkeyEncoding();
    /// @dev URL is empty.
    error EmptyURL();
    /// @dev URL exceeds `MAX_URL_LENGTH` bytes.
    error URLTooLong(uint256 length);
    /// @dev URL is not an `https://` URL with a host and without userinfo, query,
    /// fragment, whitespace or non-ASCII bytes.
    error InvalidURL();
    /// @dev `authData` exceeds `MAX_AUTH_DATA_LENGTH` bytes.
    error AuthDataTooLong(uint256 length);
    /// @dev The builder is not in the list.
    error NotRegistered();
    /// @dev The requested builder index is out of range.
    error IndexOutOfBounds();

    // ---------------------------------------------------------------------
    // IBuilderList
    // ---------------------------------------------------------------------

    /// @inheritdoc IBuilderList
    function builderCount() external view returns (uint256) {
        return _builders.length;
    }

    /// @inheritdoc IBuilderList
    function getBuilderAtIndex(
        uint256 index
    ) external view returns (BuilderRecord memory) {
        if (index >= _builders.length) revert IndexOutOfBounds();
        return _builders[index];
    }

    /// @inheritdoc IBuilderList
    function getBuilders(
        uint256 offset,
        uint256 limit
    ) external view returns (BuilderRecord[] memory page) {
        uint256 count = _builders.length;
        if (offset >= count) return new BuilderRecord[](0);
        uint256 end = count - offset < limit ? count : offset + limit;
        page = new BuilderRecord[](end - offset);
        for (uint256 i = offset; i < end; ++i) {
            page[i - offset] = _builders[i];
        }
    }

    /// @inheritdoc IBuilderList
    function getBuilder(
        bytes calldata pubkey
    ) external view returns (BuilderRecord memory) {
        return _builders[_requireIndex(keccak256(pubkey)) - 1];
    }

    /// @inheritdoc IBuilderList
    function isBuilderRegistered(
        bytes calldata pubkey
    ) external view returns (bool) {
        return _indexByPubkeyHash[keccak256(pubkey)] != 0;
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    /// @dev Validate the encoding of a compressed G1 pubkey: 48 bytes, compression flag
    /// set, infinity flag clear. Curve membership is checked by BLS verification where used.
    function _validatePubkey(bytes calldata pubkey) internal pure {
        if (pubkey.length != 48) revert InvalidPubkeyLength(pubkey.length);
        uint8 flags = uint8(pubkey[0]);
        if (flags & 0x80 == 0 || flags & 0x40 != 0)
            revert InvalidPubkeyEncoding();
    }

    /// @dev Validate a builder record's URL and auth data.
    /// The URL must be lowercase-scheme `https://`, have a non-empty host, consist of
    /// printable ASCII (internationalized hosts must be punycode), and contain no
    /// userinfo, query, fragment or backslash (the at-sign, question mark and hash
    /// characters are rejected anywhere after the scheme).
    function _validateEndpoint(
        string calldata url,
        bytes calldata authData
    ) internal pure {
        bytes calldata u = bytes(url);
        uint256 len = u.length;
        if (len == 0) revert EmptyURL();
        if (len > MAX_URL_LENGTH) revert URLTooLong(len);
        if (authData.length > MAX_AUTH_DATA_LENGTH)
            revert AuthDataTooLong(authData.length);

        // "https://" plus at least one host byte.
        if (len <= 8 || bytes8(u[0:8]) != bytes8("https://"))
            revert InvalidURL();
        if (u[8] == "/" || u[8] == ":") revert InvalidURL();

        for (uint256 i = 8; i < len; ++i) {
            bytes1 c = u[i];
            if (
                c <= 0x20 ||
                c >= 0x7f ||
                c == "@" ||
                c == "?" ||
                c == "#" ||
                c == "\\"
            ) revert InvalidURL();
        }
    }

    /// @dev Insert a new record or overwrite the existing one for `pubkey`.
    function _upsert(
        bytes32 pkHash,
        bytes calldata pubkey,
        string calldata url,
        bytes calldata authData
    ) internal {
        uint256 idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) {
            _builders.push(
                BuilderRecord({
                    pubkey: pubkey,
                    url: url,
                    authData: authData,
                    updatedAt: uint64(block.timestamp)
                })
            );
            _indexByPubkeyHash[pkHash] = _builders.length;
        } else {
            BuilderRecord storage r = _builders[idx - 1];
            r.url = url;
            r.authData = authData;
            r.updatedAt = uint64(block.timestamp);
        }
        emit BuilderRegistered(pkHash, pubkey, url, authData);
    }

    /// @dev Swap-and-pop removal of the record at 1-based `idx`.
    function _remove(
        bytes32 pkHash,
        uint256 idx,
        bytes calldata pubkey
    ) internal {
        uint256 lastIdx = _builders.length;
        if (idx != lastIdx) {
            BuilderRecord storage last = _builders[lastIdx - 1];
            _builders[idx - 1] = last;
            _indexByPubkeyHash[keccak256(last.pubkey)] = idx;
        }
        _builders.pop();
        delete _indexByPubkeyHash[pkHash];
        emit BuilderDeregistered(pkHash, pubkey);
    }

    /// @dev Return the 1-based index for `pkHash`, reverting if not registered.
    function _requireIndex(bytes32 pkHash) internal view returns (uint256 idx) {
        idx = _indexByPubkeyHash[pkHash];
        if (idx == 0) revert NotRegistered();
    }
}
