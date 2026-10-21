# Synthetic edit-only durability tests

Test-only experiment. Not production-ready and not connected to any production database.

The baseline folder is the unchanged original offline synthetic prototype and46 tests, protected by SHA256SUMS.txt. The integration folder is a NEW persistence candidate that reuses its preview validation, plus16 real MongoDB integration tests. Independent owner authentication remains a harness test double; default authority fails closed. There are no real credentials, record IDs, customer data or production endpoints.

The workflow uses a standard GitHub-hosted Ubuntu24.04 runner, an official Mongo7.0.45 Linux AMD64 image pinned to registry digest, localhost port27191, synthetic data, fixed driver versions and a10-minute job timeout. No secrets, deployments, cloud services, self-hosted runners or production writes. No merge authorization is implied.

Coverage: atomic edit/audit/single-use consumption;64 competing replay attempts; persistent replay rejection; stale multi-record rollback; precommit failure; acknowledgment loss; reconciliation fencing; worker crash at reservation/edit/commit; actual mongod SIGKILL/restart at those stages; prohibited business operations; missing authority.

Important boundaries: this is a single-node replica set, not a multi-node failover or network-partition test. External writers must preserve revisions; an unversioned ABA is outside the guarantee. A passing run does not configure real owner authorization or authorize deployment.

Registry manifest queried on2026-10-21: mongo:7.0.45 Linux AMD64 sha256:6dad6a5e2addb71d84eb417fcbcba0e11d096669917f8e8c26607cd7b52f9495.
