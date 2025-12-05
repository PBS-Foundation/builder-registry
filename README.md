# Builder Registry — On-Chain Curated List of Ethereum Builders for ePBS [EIP-7732](https://eips.ethereum.org/EIPS/eip-7732)

> **⚠️ Status: In Development**  
> This contract is currently under active development. The implementation may change before production deployment.

## Overview

The **Builder Registry** is an on-chain contract that allows trusted *curators* to publish structured metadata about Ethereum block builders.

Proposers and clients can query:

- All builders curated by multiple entities  
- Active builders  
- Recommended builders  
- Builders supporting trusted &/or trustless payments  
- OFAC-compliant builders  
- Blob-supporting builders (EIP-4844)

Each curator manages their own namespace. Curators cannot modify or affect builders added by others.

Ownership follows a multisig-safe model: the contract has a single `owner`, expected to be a Gnosis Safe.

---

## Motivation

Under ePBS, proposers will be able to choose which builders they accept bids from. A curated list helps them query for builders that comply with their specific requirements.

The Builder Registry provides:

- A neutral, shared on-chain source of metadata  
- Trustless updates by authorized curators  
- A simple query interface for proposer software  

---

## Contract Features

### Curator Management (Owner Only)

Owner-only functions:

- `registerCurator(address curator, string metadataURI)`  
- `updateCuratorMetadata(address curator, string metadataURI)`  
- `unregisterCurator(address curator)`  
- `setOwner(address newOwner)`

The `owner` should be a multisig Safe.

---

### Builder Metadata (Curator Only)

Each curator can publish metadata for builders:

- `active`  
- `recommended`  
- `trustedPayment`  
- `trustlessPayment`  
- `ofacCompliant`  
- `blobSupport`

Curator functions:

- `setBuilder(address builder, BuilderInfo info)`  
- `removeBuilder(address builder)`

Builder are completely removed from both the mapping and the list.

---

## Data Structures

### Curator

```solidity
struct Curator {
    bool exists;
    string metadataURI;
}
```

### BuilderInfo

```solidity
struct BuilderInfo {
    bool active;
    bool recommended;
    bool trustedPayment;
    bool trustlessPayment;
    bool ofacCompliant;
    bool blobSupport;
}
```
---

## Events

- `OwnerChanged(address oldOwner, address newOwner)`  
- `CuratorRegistered(address curator, string metadataURI)`  
- `CuratorUpdated(address curator, string metadataURI)`  
- `CuratorUnregistered(address curator)`  
- `BuilderSet(address curator, address builder, ...)`  
- `BuilderRemoved(address curator, address builder)`  

These events make the registry indexable and observable off-chain.

---

## View Functions (Proposer-Facing)

Read-only functions that proposer clients can call:

- `getAllBuilders(address curator)`  
  - Returns all registered builders for the given curator.

- `isBuilderRegistered(address curator, address builder)`  
  - Returns `true` if the builder is registered for the given curator.

- `getBuildersByFilter(address curator, BuilderInfo filter, uint8 filterMask)`  
  - Returns builders matching the specified filter criteria using a bitmask system.
  - **Filter Mask Bits:**
    - Bit 0 (0x01): `active`
    - Bit 1 (0x02): `recommended`
    - Bit 2 (0x04): `trustedPayment`
    - Bit 3 (0x08): `trustlessPayment`
    - Bit 4 (0x10): `ofacCompliant`
    - Bit 5 (0x20): `blobSupport`
  - Only fields where the corresponding bit is set in `filterMask` are checked.
  - The `filter` parameter specifies the exact values to match against.

- `buildersByCurator(address curator, address builder)`  
  - Returns the full `BuilderInfo` struct for a `(curator, builder)` pair.

Each curator has an independent namespace; one curator's data does not affect another's.

---

## Usage Examples

### Get all builders

```solidity
address[] memory all = registry.getAllBuilders(curator);
```

### Check if a builder is registered

```solidity
bool registered = registry.isBuilderRegistered(curator, builder);
```

### Get active builders

```solidity
BuilderRegistry.BuilderInfo memory filter = BuilderRegistry.BuilderInfo({
    active: true,
    recommended: false,
    trustedPayment: false,
    trustlessPayment: false,
    ofacCompliant: false,
    blobSupport: false
});
uint8 filterMask = 0x01; // bit 0 = active
address[] memory active = registry.getBuildersByFilter(curator, filter, filterMask);
```

### Get recommended builders

```solidity
BuilderRegistry.BuilderInfo memory filter = BuilderRegistry.BuilderInfo({
    active: true,
    recommended: true,
    trustedPayment: false,
    trustlessPayment: false,
    ofacCompliant: false,
    blobSupport: false
});
uint8 filterMask = 0x03; // bit 0 = active, bit 1 = recommended
address[] memory rec = registry.getBuildersByFilter(curator, filter, filterMask);
```

### Get blob-supporting builders

```solidity
BuilderRegistry.BuilderInfo memory filter = BuilderRegistry.BuilderInfo({
    active: true,
    recommended: false,
    trustedPayment: false,
    trustlessPayment: false,
    ofacCompliant: false,
    blobSupport: true
});
uint8 filterMask = 0x21; // bit 0 = active, bit 5 = blobSupport
address[] memory blobBuilders = registry.getBuildersByFilter(curator, filter, filterMask);
```

### Filter builders (trusted payment + OFAC-compliant)

```solidity
BuilderRegistry.BuilderInfo memory filter = BuilderRegistry.BuilderInfo({
    active: true,
    recommended: false,
    trustedPayment: true,
    trustlessPayment: false,
    ofacCompliant: true,
    blobSupport: false
});
uint8 filterMask = 0x15; // bit 0 = active, bit 2 = trustedPayment, bit 4 = ofacCompliant
address[] memory filtered = registry.getBuildersByFilter(curator, filter, filterMask);
```

---

## Ownership & Security Model

- The registry has a single `owner` address.  
- Recommended: set `owner` to a Gnosis Safe multisig.  
- Only the `owner` can:
  - register curators  
  - update curator metadata  
  - unregister curators  
  - transfer ownership  

Curators have write access only within their own builder namespace.

---

## Developer Setup

### Install dependencies

```bash
forge install
```

### Run tests

```bash
forge test -vv
```