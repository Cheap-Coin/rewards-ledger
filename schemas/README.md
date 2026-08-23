# Evidence schemas

Schemas use JSON Schema draft 2020-12 and are versioned, append-only public
interfaces. `common-v1` contains shared Solana address, signature, hash, amount,
cluster, and URI definitions. Every evidence object rejects additional fields.

Create a new schema version for a breaking change; never rewrite a schema used by
published evidence.
