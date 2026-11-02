# ERC-8218 Builder Registry

Reference implementations for [ERC-8218: Builder Discovery](https://github.com/ethereum/ERCs/pull/1650), an on-chain discovery mechanism for block builders participating in enshrined proposer-builder separation ([EIP-7732](https://eips.ethereum.org/EIPS/eip-7732)).

> [!WARNING]
> ERC-8218 is a draft proposal and these contracts are under development. No canonical deployment is documented yet. Do not use them in production without an independent security review.

## Why this exists

EIP-7732 introduces staked builders at the Ethereum consensus layer, but clients also need a way to discover where those builders can be contacted. ERC-8218 defines a minimal record for that purpose:

```solidity
struct BuilderRecord {
    bytes pubkey; // 48-byte compressed BLS12-381 public key
    string fqdn;  // builder API endpoint name
}
```

The registry is a discovery layer, not proof that a builder is active or sufficiently staked. Clients must cross-reference each public key against the EIP-7732 builder registry in beacon state and apply their own balance, reachability, and policy checks.

ERC-8218 supports two complementary models:

- **Open registry:** builders register themselves by proving control of their BLS key.
- **Permissioned registry:** an owner curates a list according to an external policy.

Both expose the same `IBuilderList` read interface. Each deployed contract represents one list; consumers can query one or several registry contracts.

## Contracts

### `OpenBuilderRegistry`

[`src/OpenBuilderRegistry.sol`](src/OpenBuilderRegistry.sol) implements both `IBuilderRegistry` and `IBuilderList`.

A builder registers or updates its FQDN by submitting:

- its 48-byte compressed BLS12-381 public key;
- a non-empty FQDN of at most 253 bytes;
- a public-key-scoped nonce; and
- a valid BLS signature.

The registration signature covers:

```solidity
abi.encode(block.chainid, address(this), pubkey, fqdn, nonce)
```

Deregistration uses a separate signed message:

```solidity
abi.encode(block.chainid, address(this), pubkey, nonce)
```

Including the chain ID and registry address prevents signatures from being replayed across chains or registry deployments. A successfully consumed nonce can only be used once for a given public key.

Signature verification uses the EIP-2537 BLS12-381 precompiles and the `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` ciphersuite. The implementation accepts 192-byte Zcash-layout or 256-byte EIP-2537-layout uncompressed G2 signatures.

### `PermissionedBuilderRegistry`

[`src/PermissionedBuilderRegistry.sol`](src/PermissionedBuilderRegistry.sol) implements `IBuilderList` with owner-controlled admission.

The owner can:

- register a builder;
- update the FQDN associated with an existing public key;
- deregister a builder; and
- transfer ownership.

The owner should be a suitably governed account, such as a multisig, when a permissioned registry is deployed for operational use. The admission policy itself is intentionally outside ERC-8218.

### Shared interfaces

[`src/interfaces/IERC8218.sol`](src/interfaces/IERC8218.sol) defines:

```solidity
interface IBuilderList {
    function builderCount() external view returns (uint256);

    function getBuilderAtIndex(uint256 index)
        external
        view
        returns (BuilderRecord memory);
}
```

`IBuilderRegistry` additionally defines BLS-authorized registration and deregistration for permissionless implementations.

## Reading a registry

Clients enumerate a registry using `builderCount()` and `getBuilderAtIndex(index)`:

```solidity
uint256 count = registry.builderCount();

for (uint256 i; i < count; ++i) {
    BuilderRecord memory builder = registry.getBuilderAtIndex(i);
    // Cross-reference builder.pubkey against beacon state before use.
}
```

Indexes are enumeration positions, not permanent builder identifiers. Deregistration uses swap-and-pop removal, so removing a builder can change the index of another record.

## Trust and validation boundaries

Consumers must not treat registry inclusion as sufficient evidence that a builder is safe or eligible. A client is expected to:

1. verify that the BLS public key belongs to an active EIP-7732 builder;
2. apply its required minimum effective balance or stake policy;
3. validate and resolve the advertised endpoint;
4. perform the builder handshake when that protocol is specified; and
5. apply any local reputation, availability, compliance, or allowlist policy.

The contracts currently enforce only FQDN byte length and non-emptiness; they do not validate DNS syntax, endpoint reachability, TLS, or ownership of the resolved domain.

## Development

The project uses [Foundry](https://book.getfoundry.sh/) and Python helpers for independent BLS test-vector generation.

Install Solidity dependencies:

```bash
forge install
```

Install Python test dependencies in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r script/requirements.txt
```

Run formatting, compilation, and tests:

```bash
forge fmt --check
forge build --sizes
forge test -vvv
```

FFI is enabled in `foundry.toml` because the cryptographic tests call the Python reference scripts.

## Repository layout

```text
src/interfaces/IERC8218.sol         ERC-8218 data types and interfaces
src/OpenBuilderRegistry.sol         Permissionless BLS-authorized registry
src/PermissionedBuilderRegistry.sol Owner-curated registry
src/lib/BLS12381.sol                BLS verification and hash-to-curve logic
test/                               Unit, fuzz, and cryptographic cross-check tests
script/bls_sign.py                  Independent signature generation for tests
script/bls_htc.py                   Independent hash-to-curve cross-checks
```

## Legacy research artifacts

`BuilderRegistry.sol`, `BuilderRegistryV1.sol`, and `curatedListPBSF_WIP.json` belong to an earlier design based on EVM addresses, curator namespaces, and policy metadata such as payment type or OFAC compliance. They are not part of the minimal ERC-8218 interface and are retained for research history.

`Counter.sol` and its associated test and script are Foundry template artifacts and are unrelated to ERC-8218.

## Standardization status

The specification can be read on the [builder-discovery branch](https://github.com/canercidam/ERCs/blob/builder-discovery/ERCS/erc-8218.md) and is currently proposed for standardization in [ethereum/ERCs#1650](https://github.com/ethereum/ERCs/pull/1650). Interface and implementation details may change as review continues.
