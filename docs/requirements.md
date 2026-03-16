# WG RADIUS Daemon Requirements

## Goal

Develop a userspace daemon that integrates WireGuard with RADIUS without:

- modifying the Linux kernel;
- rebuilding the kernel;
- moving WireGuard implementation out of kernel space.

## High-Level Idea

The daemon must provide an external control plane around WireGuard peers:

- track WireGuard peer state;
- authorize peers through RADIUS;
- send accounting events;
- handle CoA and Disconnect;
- apply session parameters returned by RADIUS, including speed limits.

## 1. Client Identification

- User identifier: WireGuard peer public key.
- RADIUS stores the list of allowed public keys.
- Public key is sent in `Access-Request` as the primary client identifier.

Additional service attributes may be sent:

- WireGuard interface name;
- client endpoint;
- assigned IP / `AllowedIPs`;
- `NAS-Identifier` / `NAS-IP-Address`;
- `Calling-Station-Id` / `User-Name` according to agreed mapping.

Operational clarification:

- RADIUS logic is applied per configured WireGuard interface.
- The daemon must support configuration as one or more `interface -> RADIUS profile` bindings.
- The preferred deployment model is multi-instance or logically equivalent multi-profile handling, where each WireGuard interface can use its own:
  - auth server;
  - accounting server;
  - CoA settings;
  - shared secret;
  - policy mapping and local handling rules.
- A peer is always evaluated in the context of the specific WireGuard interface where it exists.

## 2. Authorization

The daemon must support two authorization trigger modes:

- on peer appearance in configuration;
- on first handshake.

The mode is selected in configuration.

Authorization flow:

1. Detect a new peer or its first handshake.
2. Build and send `Access-Request` to the RADIUS server.
3. If `Access-Accept` is received:
   - mark peer as authorized;
   - apply allowed session parameters;
   - start accounting.
4. If `Access-Reject` is received:
   - remove the peer or block it locally;
   - do not treat the session as active.

## 3. WireGuard Event Source

The daemon must obtain peer and session state via userspace mechanisms only.

Preferred:

- netlink / `wgctrl` / WireGuard userspace API.

Allowed for prototype:

- periodic polling of `wg show`.

The daemon must track:

- new peer appearance;
- peer removal;
- first handshake;
- handshake refresh;
- current RX/TX counters;
- prolonged inactivity.

## 4. Accounting

The daemon must send standard RADIUS accounting events:

- `Acct-Start` on active session start;
- `Acct-Interim-Update` periodically, with configurable interval;
- `Acct-Stop` on session end, peer removal, or when the session becomes inactive.

Accounting payload must include:

- peer public key;
- WireGuard interface;
- assigned IP;
- endpoint;
- session start time;
- session duration;
- inbound and outbound traffic;
- stop reason.

Purpose of accounting:

- session statistics in RADIUS;
- active session tracking.

Operational clarification for inactivity:

WireGuard does not expose a canonical built-in notion of “session inactive” equivalent to stateful VPN concentrators. Therefore, inactivity must be defined by daemon policy rather than assumed from WireGuard alone.

For this project, inactivity should be treated as a configurable derived condition based on one or more of:

- no handshake refresh for longer than configured `inactive_timeout`;
- no RX/TX counter changes for longer than configured `inactive_timeout`;
- optionally both conditions together, if stricter behavior is desired.

Requirements for this rule:

- the inactivity strategy must be configurable;
- defaults must be conservative to avoid false session termination;
- the daemon must record which inactivity rule caused `Acct-Stop`;
- the chosen rule must be documented as an operator policy, not presented as a native WireGuard session-state fact.

## 5. CoA / Disconnect

The daemon must support reverse session control from RADIUS:

- listen on UDP/3799;
- accept `Disconnect-Request`;
- accept `CoA-Request`.

Behavior:

`Disconnect-Request`:

- find a peer by public key or another agreed identifier;
- disconnect it by removing the peer or switching it to blocked state.

`CoA-Request`:

- modify parameters of an active session;
- apply new limits or settings without daemon restart when possible.

## 6. Required RADIUS Attributes

Minimum support:

- client identifier by public key;
- accounting attributes;
- CoA / Disconnect attributes.

Additional required support:

- client speed limiting attributes.

### Traffic Shaping / Rate Limiting

RADIUS must be able to return attributes that define client speed:

- ingress rate;
- egress rate;
- optionally burst / ceil / priority.

Important:

WireGuard does not natively apply RADIUS speed attributes, so rate limiting must be implemented externally in userspace or through the Linux networking stack.

Preferred implementation:

- shaping / policing through `tc`.

Acceptable implementation variants:

- `tc qdisc/class/filter`;
- `ifb` for split ingress control if needed;
- another technically correct scheme that does not require changes to the kernel or WireGuard.

The shaping module must:

- read speed attributes after `Access-Accept`;
- map them to a specific peer;
- apply traffic limits;
- update shaping parameters for an active peer on `CoA-Request`.

If complete per-peer limiting is not feasible through WireGuard alone, it must be solved transparently at Linux networking stack level.

## 7. Attribute Application Model

After `Access-Accept`, the daemon must be able to apply to a peer:

- session allow / deny;
- `AllowedIPs`, if used by the deployment;
- `Session-Timeout` / idle timeout, if required;
- speed limits;
- other agreed RADIUS attributes.

Supported attributes must be defined in a separate mapping table:

`RADIUS attribute -> daemon action`

## 8. Daemon Configuration

The daemon must have a configuration file containing:

- RADIUS auth server address and port;
- accounting server address and port;
- CoA address and port;
- shared secret;
- WireGuard interface name;
- authorization mode;
- `Acct-Interim-Update` interval;
- timeouts and retry policy;
- reject handling mode;
- logging parameters;
- shaping application rules;
- mapping of RADIUS attributes to local actions.

## 9. Logging and Diagnostics

The daemon must log:

- peer detection;
- authorization attempts;
- RADIUS responses;
- accounting start / stop;
- shaping application and changes;
- CoA / Disconnect events;
- network errors, timeouts, malformed attributes.

Desired:

- `info` / `debug` / `error` levels;
- clean output for `systemd-journal`.

## 10. Operational Deliverables

The project output must include:

- standalone daemon;
- configuration file;
- `systemd` unit;
- startup instructions;
- supported RADIUS attribute documentation;
- example integration with a RADIUS server.

## 11. Constraints

Not allowed:

- Linux kernel modification;
- kernel rebuild;
- changes to WireGuard kernel implementation;
- dependency on a custom WireGuard module.

All logic must run in userspace.

## 12. Delivery Stages

### Stage 1. Prototype

- peer tracking;
- `Access-Request` / `Access-Accept` / `Access-Reject`;
- basic peer control;
- `Acct-Start` / `Acct-Stop`.

### Stage 2. Full Accounting

- `Acct-Interim-Update`;
- activity tracking;
- correct session termination.

### Stage 3. CoA / Disconnect

- `Disconnect-Request` handling;
- `CoA-Request` handling.

### Stage 4. Shaping

- parse speed attributes from RADIUS;
- apply per-peer rate limits;
- update shaping through `CoA`.
