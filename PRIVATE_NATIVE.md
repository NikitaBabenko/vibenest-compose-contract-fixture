# Private native candidate boundaries

This is a disposable synthetic fixture for the existing native lifecycle matrix.
The repository is public; this does not validate private GitHub App source access.
The fixture Python render utility is used; platform renderer 2.0.0 does not
participate and its production acceptance remains false. Native execution and
production readiness cannot be inferred from local unit tests.

Both services use `memswap_limit == mem_limit`. The independent pre-start gate
requires an explicit integer Docker `HostConfig.MemorySwap` equal to the exact
assigned memory limit. Missing, unknown, unlimited and mismatched values refuse.

The missing-retained-volume negative requires a one-shot authenticated receipt
from the helper's retained-volume inspection stage. The helper constructs it only
after a successful complete volume listing, exact assigned-name absence, and zero
volume-create attempts. It contains exact immutable scope, fixed stage/reason,
the assigned name hash, sorted full-inventory hash, and `createIssued: false`.
Raw names, config and credentials are not included in that receipt. The runner
checks a separate fresh complete inventory against both hashes and the exact
assigned missing name. Failed jobs without this receipt, wrong-stage errors,
different scope or runtime artifacts cannot satisfy the negative scenario.

Artifact/refusal submissions are mutually exclusive per scope and one-shot;
refusals cannot unlock the fixture start gate. Only the runner control pipe can
read a retained refusal. A lost upload ACK can be reconciled by that read without
retrying the mutation. This proves possession of a fixture capability, not host
proof-of-possession or production start authority.

Only the release coordinator may dispatch an exact reviewed revision after the
shared disposable test slot and Actions budget checks. No independent dispatch,
push, customer application operations or production release is part of this
candidate's local preparation.
