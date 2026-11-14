# RBAC verification results

## Automated checks

The integration suite now exercises successful login and authenticated `/api/auth/me` access for all seven system roles. It also rejects unauthenticated and malformed-token requests, verifies expired/revoked session denial, checks role-gated administration, and covers role escalation, organization approval eligibility, membership linkage, permission bounds, and privileged audit writes.

Run on 2026-11-15 with Node 22.23.5 and the installed project dependencies:

- `vitest run`: 10 test files passed; 165 tests passed.
- `tsc --noEmit`: passed.
- `tsc -p tsconfig.build.json`: passed.

These tests use mocked persistence. They verify direct HTTP routes through Supertest but do not exercise a live MongoDB replica set, mail delivery, or deployed infrastructure.

## Findings

No authorization defect was reproduced in the implemented endpoints covered by this suite. Public registration cannot set system roles; permission overrides are bounded by role; organization titles do not create platform permissions; application review requires an active, verified applicant and writes an audit record; access changes revoke sessions and are audited.

The supplied role specification describes features that this repository does not implement, so their isolation and authorization behavior cannot yet be verified:

- Organization administration CRUD and organization invitation/acceptance flows.
- Pending, suspended, or removed membership lifecycle endpoints and organization resource isolation.
- Grower and florist listing/profile CRUD and cross-owner listing checks.
- Content moderation beyond reviewing business/organization applications.

These are implementation gaps, not passing RBAC checks. Add the APIs and ownership/status enforcement before claiming acceptance for those workflows. The full scope boundaries are also listed in [access-control.md](../access-control.md).
