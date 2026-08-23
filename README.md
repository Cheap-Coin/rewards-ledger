# CheapCoin rewards ledger

Public, MIT-licensed, append-only evidence for Solana community campaigns and
program deployments. The active ledger contains campaign manifests, allocation
lists, unsigned transaction commitments, finalized signatures, reconciliation
reports, deployment records, public rules, and notices.

## Status and boundaries

CheapCoin is in `PRELAUNCH`. The checked-in JSON records under `fixtures/` are
synthetic devnet validation vectors and are not launches, rewards, entitlements,
partners, or executed mainnet activity. Active evidence directories are empty
until the owner publishes independently reviewed records.

This repository never publishes X credentials, provider identity IDs, wallet-to-X
mappings, private partner terms, signer keys, or signed transaction bytes. X
analytics do not determine campaign recipients here: each allocation is supplied
as an independent artifact with an exact budget and finalized snapshot slot.

Small campaigns may record Squads-approved native SOL or SPL batches. Large
campaigns must reference an audit-pinned, manifest-verified Merkle rewards
deployment. Native SOL wrapping/unwrapping, when applicable, is represented by
separate transaction evidence; it is never inferred.

The V1 evidence contract accepts legacy SPL Token campaign transfers only.
Token-2022 campaign evidence requires a future schema that commits to extension,
transfer-fee, and transfer-hook validation rather than treating all extensions as
equivalent.

## Verify and publish

```bash
pnpm install --frozen-lockfile
pnpm check
```

The validator compiles all draft-2020-12 schemas, requires canonical JSON and
strict fields, rejects normalized private/signing fields and credential-bearing
URIs, validates decoded Solana addresses and signatures, prevents fixture records
from being referenced by published evidence, reproduces allocation totals, checks
unique sorted recipients and transaction sequences, verifies linked record hashes
and identities, checks transaction finality, and proves reconciliation
conservation. `pnpm format:evidence` only canonicalizes JSON; it does not fix
commitments or authorize publication.

Merkle evidence is pinned to the Solana Foundation rewards program ID
`REWArDioXgQJ2fZKkfu9LCLjQfRwYWVVfsvcsR5hoXi` and the OtterSec-audited source
commit `aa1cfd9276375e44e57d1917d110ff095fb6d475`. That pin is necessary but not
sufficient: no mainnet campaign may be published until an independently verified
deployment record proves that the deployed program binary corresponds to that
source and audit baseline.

Publication is append-only. Add a new version or superseding record instead of
editing published schemas, rules, allocations, manifests, transactions,
deployments, or reconciliations. Every value-moving record requires independent
review of asset, programs, treasury, recipients/root, exact total, expiration,
simulation, and finalized signatures.

The CI checker treats the first commit whose trusted base lacks
`schemas/common-v1.schema.json` as the one-time Solana V1 bootstrap. From the
next trusted base onward, every protected schema, rule, and evidence path is
strictly append-only.

Canonical launch/program identity comes from the public protocol repository's
signed manifests and must agree with these records. The developer retains commit
and push control.
