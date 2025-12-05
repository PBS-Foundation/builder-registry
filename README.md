# Builder Registry — On-Chain Curated List of Ethereum Builders

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

Under ePBS, proposers will be able to choose which builders they accept trustless payments from. A curated list helps them query for builders that comply with their specific requirements.

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

- `setBuilder(address builder, BuilderInfoInput info)`  
- `removeBuilder(address builder)`

Builder removal uses soft delete: flags are cleared but the address stays in the internal list for gas efficiency.

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
    bool exists;
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
- `CuratorUnregistered(address curator)`  
- `BuilderSet(address curator, address builder, ...)`  
- `BuilderRemoved(address curator, address builder)`  

These events make the registry indexable and observable off-chain.

---

## View Functions (Proposer-Facing)

Read-only functions that proposer clients can call:

- `getAllBuilders(address curator)`  
  - All builders where `exists == true` for that curator.

- `getActiveBuilders(address curator)`  
  - Builders where `exists == true` and `active == true`.

- `getRecommendedBuilders(address curator)`  
  - Builders where `exists == true`, `active == true`, and `recommended == true`.

- `getBlobBuilders(address curator)`  
  - Builders where `exists == true`, `active == true`, and `blobSupport == true`.

- `getBuildersByFilter(address curator, bool onlyTrustedPayment, bool onlyTrustlessPayment, bool onlyOFAC)`  
  - Builders that exist, are active, and satisfy the filter flags.

- `buildersByCurator(address curator, address builder)`  
  - Returns the full `BuilderInfo` struct for a `(curator, builder)` pair.

Each curator has an independent namespace; one curator’s data does not affect another’s.

---

## Usage Examples

### Get recommended builders

```solidity
address[] memory rec = registry.getRecommendedBuilders(curator);
```

### Get blob-supporting builders

```solidity
address[] memory blobBuilders = registry.getBlobBuilders(curator);
```

### Filter builders (trusted + OFAC-compliant)

```solidity
address[] memory filtered = registry.getBuildersByFilter(
    curator,
    true,   // onlyTrustedPayment
    false,  // onlyTrustlessPayment
    true    // onlyOFAC
);
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

Builders are removed via soft delete: `exists` and all flags are set to `false`, but the address remains in the array to avoid O(n) gas costs and griefing.

Example: transfer ownership to a Safe:

```solidity
registry.setOwner(SAFE_ADDRESS);
```

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

The test suite covers:

- owner permission checks  
- curator registration, metadata update, and removal  
- builder insertion, flag updates, and removal  
- `getAllBuilders`, `getActiveBuilders`, `getRecommendedBuilders`  
- `getBlobBuilders` and `blobSupport`  
- `getBuildersByFilter`  
- namespace isolation between curators  
- soft-delete behavior  

---

## Deployment Workflow

1. Deploy the contract from an EOA.  
2. Create or choose a Gnosis Safe multisig.  
3. Transfer ownership of the registry to the Safe:

   ```solidity
   registry.setOwner(SAFE_ADDRESS);
   ```

4. From the Safe, call `registerCurator` to add trusted curators.  
5. Curators call `setBuilder` / `removeBuilder` to maintain their builder lists.  
6. Proposer clients read from the registry and follow curated sets automatically.

---

