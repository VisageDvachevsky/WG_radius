# WG RADIUS Daemon Implementation Plan

## Working Assumptions

- Target platform: Linux with in-kernel WireGuard.
- The daemon runs in userspace as a privileged service.
- Prototype may use polling, but the production path should prefer a direct WireGuard control API.
- Per-peer shaping is not a WireGuard feature; it must be implemented through Linux traffic control.

## Proposed Architecture

The daemon should be split into explicit modules:

1. `config`
   - parse and validate daemon configuration;
   - load attribute mapping rules;
   - expose defaults and feature toggles;
   - support one or more `WireGuard interface -> RADIUS profile` bindings.

2. `wg-observer`
   - read peer state from WireGuard;
   - detect new peers, removed peers, first handshake, handshake updates, RX/TX changes;
   - emit normalized internal events.

3. `session-manager`
   - own the peer/session state machine;
   - decide when authorization starts;
   - track authorized, pending, blocked, inactive and terminated sessions;
   - coordinate accounting, timers and policy application;
   - evaluate inactivity using configurable daemon policy rather than assuming a native WireGuard session state.

4. `radius-client`
   - send `Access-Request`;
   - send accounting packets;
   - correlate replies, retries and timeouts;
   - normalize RADIUS attributes into internal policy objects.

5. `coa-server`
   - listen on UDP/3799;
   - validate sender and shared secret;
   - parse `Disconnect-Request` and `CoA-Request`;
   - hand off actionable events to `session-manager`.

6. `peer-controller`
   - apply allow/deny actions to WireGuard peers;
   - remove peer, update `AllowedIPs`, or place it in a blocked state;
   - keep WireGuard operations isolated from business logic.

7. `shaper`
   - translate internal rate policy into `tc` commands or netlink operations;
   - maintain per-peer shaping handles;
   - update and remove shaping on session changes and CoA.

8. `logging/metrics`
   - structured logs for `systemd-journald`;
   - counters for auth attempts, accepts, rejects, accounting, CoA and errors.

## Core State Model

Suggested peer/session states:

- `discovered`
- `pending_auth`
- `authorized`
- `blocked`
- `inactive`
- `terminated`

Key transitions:

- `discovered -> pending_auth`
- `pending_auth -> authorized`
- `pending_auth -> blocked`
- `authorized -> inactive`
- `authorized -> terminated`
- `blocked -> terminated`

This keeps RADIUS behavior explicit and prevents accounting from starting before authorization success.

## Technical Decisions To Make Early

1. Implementation language
   - Strong candidates: Go or Rust.
   - For a first delivery, Go is pragmatic because it has mature networking support, easy service packaging and simpler integration with external commands when `tc` is needed.

2. WireGuard integration method
   - Prototype: call `wg show all dump` on a polling interval.
   - Next step: switch to a library or netlink-based integration to reduce parsing fragility.

3. RADIUS library strategy
   - Prefer an existing library rather than implementing packet encoding from scratch.
   - Need support for Access, Accounting and CoA/Disconnect packet families.

4. Blocking strategy for rejected peers
   - Option A: remove peer from interface.
   - Option B: keep peer present but neutralize routing/traffic policy.
   - For prototype, peer removal is simpler and easier to reason about.

5. Per-peer shaping model
   - Egress can usually be controlled on the WG interface.
   - Ingress may require `ifb` mirroring or a deployment-specific compromise.
   - This part needs a concrete Linux traffic-control design before coding the shaping module.

6. Interface/profile operating model
   - The service should not assume a single global WireGuard interface.
   - Preferred runtime model: one daemon instance per interface, or one daemon process with multiple interface-scoped profiles.
   - In both variants, all auth/accounting/CoA settings must be resolved in the context of the interface where a peer is observed.

7. Inactivity policy
   - WireGuard does not define a canonical inactive session state for this use case.
   - The daemon must derive inactivity from configurable policy, for example:
     - handshake timeout;
     - traffic inactivity timeout;
     - combined handshake-and-traffic timeout.
   - `Acct-Stop` due to inactivity must include the derived stop reason, not imply a native WireGuard disconnect event.

## Recommended Phase Breakdown

### Phase 0. Design Baseline

Produce:

- daemon skeleton;
- config schema;
- internal event model;
- session state machine;
- attribute mapping table draft.

### Phase 1. Prototype

Implement:

- poll WireGuard peers;
- detect first-seen peer and first handshake;
- send `Access-Request`;
- on `Accept`, mark session active and send `Acct-Start`;
- on `Reject`, remove or block peer;
- send `Acct-Stop` on termination.

This phase proves the main control loop.

### Phase 2. Accounting Maturity

Implement:

- periodic `Acct-Interim-Update`;
- idle/inactivity detection;
- robust stop reasons;
- restart-safe session handling if needed.

### Phase 3. Dynamic Control

Implement:

- UDP listener for CoA/Disconnect;
- request validation;
- live session mutation;
- peer teardown on Disconnect.

### Phase 4. Shaping

Implement:

- policy mapping from RADIUS rate attributes;
- `tc`-backed apply/update/remove flow;
- CoA-triggered shaping refresh;
- rollback behavior if shaping fails.

## Initial Project Layout

Recommended starting structure:

```text
cmd/wg-radiusd/
internal/config/
internal/wgobserver/
internal/session/
internal/radiusclient/
internal/accounting/
internal/coa/
internal/peerctl/
internal/shaper/
internal/logging/
configs/
packaging/systemd/
docs/
```

## Immediate Next Step

The next practical move is to choose the implementation language and create the daemon skeleton for Stage 1:

- config loading;
- polling-based WireGuard observer;
- RADIUS auth client;
- minimal session manager;
- `Acct-Start` / `Acct-Stop`.

That is the smallest slice that exercises the core design without overcommitting to CoA or shaping details too early.
