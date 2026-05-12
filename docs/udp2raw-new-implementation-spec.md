# UDP2Raw New Implementation Specification

This document records the required behavior, constraints, and failure history for a future UDP2Raw implementation in the macOS client and the backend/server scripts it uses.

It intentionally does not define the next implementation plan. The next design should be written separately after these constraints are accepted.

## Scope

- Product scope: macOS client plus backend/service/server script code that the macOS client invokes.
- Protocol scope: UDP2Raw wrapping for WireGuard and AmneziaWG only.
- Current reset baseline: `7c3129e923048065b0d240bd118c9e7099a8935f`.
- Client-side UDP2Raw binary: Homebrew `udp2raw-multiplatform` (`udp2raw_mp`) on macOS.
- Server-side implementation must be compatible with the user's known-good manual setup, which reached about 600 Mbps using default UDP2Raw settings.

## Hard Requirements

1. UDP2Raw + WireGuard and UDP2Raw + AmneziaWG must pass normal internet traffic, not merely show "Connected".
2. After disconnect, normal internet must work immediately without manual cleanup.
3. DNS must not hang after disconnect. Commands such as `route -n get google.com` and `ping google.com` must return normally.
4. The app must not crash during or after disconnect.
5. Ping display must continue to work when the tunnel is connected.
6. Speed must be in the same class as the user's manual UDP2Raw backend, not the observed 20-27 Mbps range.
7. The implementation must not change UDP2Raw cipher/auth/socket-buffer defaults as a speed workaround.
8. The implementation must preserve DPI-resistance properties. In particular, do not set `--cipher-mode none` or `--auth-mode none` as a default optimization.
9. The implementation must be testable with concrete client and server diagnostics that show where traffic enters, exits, or dies.

## Explicit Non-Goals

- Do not implement a new plan in this document.
- Do not treat MTU as the primary root cause without new evidence. The user explicitly ruled this out.
- Do not treat UDP2Raw binaries/version as the primary root cause without new evidence. The user explicitly ruled this out.
- Do not solve speed by raising `--sock-buf`; high socket buffers caused unacceptable jitter in the user's testing.
- Do not solve speed by disabling UDP2Raw cipher/auth. The user wants an actual cipher because it scrambles packets and helps DPI resistance.
- Do not assume an app-level "Connected" state means the data path works.

## Required Observable States

The app state must distinguish these cases:

- UDP2Raw process started.
- Inner WireGuard/AWG backend started.
- WireGuard/AWG handshake completed.
- Tunnel can receive return packets.
- DNS through the selected resolvers works.
- Full internet probe works.

"Connected" may only be shown after the backend reaches the existing product definition of connected, and diagnostics must make it clear whether this is only a handshake or a usable data path. The previous implementation showed connected while `ping -c 3 1.1.1.1` had 100% packet loss.

## Required Diagnostics

A future implementation must include or preserve diagnostics that can be run while connected and while disconnecting.

Client diagnostics must capture:

- Installed app and service Mach-O UUIDs.
- Exact command line for `udp2raw_mp`.
- Exact command line for `wireguard-go` or `amneziawg-go`.
- Daemon status JSON, including local tunnel address, gateway, rx bytes, and tx bytes.
- macOS routes before connect, during connect, and after disconnect.
- macOS DNS state before connect, during connect, and after disconnect.
- `/var/run/amneziavpn` and `/var/run/amneziawg` runtime files.
- Recent app and service crash reports.
- Recent unified logs around connect/disconnect.

Server diagnostics must capture:

- Docker containers, network modes, entrypoints, commands, and published ports.
- `ps` for UDP2Raw/WG/AWG processes.
- `ss -lntup` / `ss -lnu` for public fake-TCP and inner UDP listeners.
- `ip addr`, `ip route`, and relevant sysctls.
- `wg show all` / `awg show all` or dumps.
- `iptables -S`, `iptables -t nat -S`, and packet counters before and during client probes.

## Current Baseline Summary

The reset baseline already has an initial UDP2Raw implementation:

- New containers: `amnezia-udp2raw-wireguard` and `amnezia-udp2raw-awg`.
- Client wrapper protocol: `Udp2RawProtocol`, inheriting the WireGuard protocol path.
- Client behavior: start `udp2raw_mp`, rewrite inner WireGuard/AWG endpoint to `127.0.0.1:<localPort>`, then start WireGuard/AWG.
- Server behavior: run WireGuard/AWG and `udp2raw` in the same container, with `udp2raw` listening publicly and forwarding to `127.0.0.1:<internalPort>`.
- Server container networking: Docker bridge path with public fake-TCP port published by Docker.

This baseline should be treated as an implementation candidate, not as validated behavior.

## Failed Approaches And Specific Issues

### 1. Initial Same-Container Docker Bridge Implementation

Shape:

- WG/AWG and server-side `udp2raw` ran in the same Docker container.
- Server `udp2raw` listened on `0.0.0.0:$UDP2RAW_PUBLIC_PORT`.
- Docker published the public fake-TCP port.
- Client ran `udp2raw_mp` locally and rewrote WG/AWG endpoint to localhost.

Observed issues:

- App could show connected while sites failed to open.
- `ping 1.1.1.1` timed out.
- DNS lookups such as `ping google.com` could hang.
- Speed was around 20-27 Mbps, far below the user's manual 600 Mbps setup.

Specific lessons:

- Docker-published fake-TCP traffic is suspect for performance and correctness. Fake-TCP should not be casually routed through Docker's port publishing/NAT path.
- Connected state and handshake are insufficient; return traffic and DNS must be validated.

### 2. Client Route Exclusion Around Localhost Endpoint

Shape:

- Client endpoint was rewritten to `127.0.0.1:<localPort>`.
- Existing macOS WireGuard route-exclusion code still treated the configured endpoint as a peer endpoint.

Observed issue:

- Route logic could attempt to exclude `127.0.0.1` through the physical gateway, which can break the local UDP2Raw socket path.

Specific lessons:

- The local rewritten endpoint and the real remote server endpoint must be kept separate.
- Route exclusion must apply to the real server IP, not localhost.
- No route should be added that sends `127.0.0.1` anywhere except loopback.

### 3. Ping-Only Fixes

Shape:

- Ping target/fallback logic was adjusted so Ping could display.

Observed issue:

- Ping visibility improved, but the tunnel still did not pass normal internet traffic.

Specific lessons:

- Ping display fixes are not connectivity fixes.
- Ping must remain an acceptance criterion, but passing Ping UI alone does not validate the UDP2Raw data path.

### 4. Disconnect Cleanup Patches

Shape:

- Cleanup was hardened around WG/AWG process termination, route deletion, DNS restore, PF cleanup, and stale runtime files.

Observed issues:

- The user still saw internet broken after disconnect in some runs.
- Manual cleanup scripts did not always recover the system.
- GUI and service crashes appeared during this phase.

Specific lessons:

- Disconnect must be modeled as an acknowledged backend lifecycle, not just "send deactivate and immediately mark disconnected".
- Cleanup must continue even if one cleanup step fails.
- DNS backup/restore must not restore poisoned Amnezia-managed DNS.
- Route cleanup must not depend only on a still-existing tracked utun name.
- Any privileged child process ownership changes must be reviewed for Qt Remote Objects lifetime side effects.

### 5. UDP2Raw Parameter Changes

Shape:

- Tried changing UDP2Raw parameters, including disabling cipher/auth and raising socket buffers.

Observed issue:

- The user explicitly rejected this direction. Their manual backend reached about 600 Mbps using default UDP2Raw settings.
- High socket buffers caused massive jitter.
- Disabling cipher/auth reduces packet scrambling and therefore weakens DPI resistance.

Specific lessons:

- Do not use UDP2Raw parameter changes as the speed fix.
- Keep default cipher/auth/socket-buffer behavior unless the user explicitly approves a specific change.

### 6. Full Host-Network Server Container

Shape:

- Ran the whole UDP2Raw WG/AWG container with `--network host`.
- This moved the inner WG/AWG interface and server-side UDP2Raw into the host network namespace.

Observed issues:

- Live connectivity broke.
- Ping stopped showing in at least one retest.
- The change altered more topology than intended.

Specific lessons:

- Moving the whole protocol container to host networking is too broad unless every consequence is accounted for.
- Host-network WG/AWG interfaces can survive container removal unless explicitly brought down.
- Host firewall/NAT rules must be designed for host namespace ownership, not Docker namespace ownership.

### 7. Host-Network UDP2Raw Sidecar Forwarding To Container Bridge IP

Shape:

- Kept WG/AWG in a normal Docker bridge container.
- Ran UDP2Raw as a host-network sidecar.
- Forwarded UDP2Raw to the main container's Docker bridge IP.

Observed issue:

- Speed remained around 20-27 Mbps.

Specific lessons:

- Removing Docker public fake-TCP publishing was not enough.
- The remaining bridge/veth/container path was still a meaningful difference from the user's manual fast topology.
- Sidecar-to-container-bridge forwarding should not be assumed fast or equivalent to manual host-local forwarding.

### 8. Host-Local Inner UDP Via Docker Loopback Publish

Shape:

- Kept WG/AWG containerized.
- Published the inner UDP port on host loopback, for example `127.0.0.1:<internal>:<internal>/udp`.
- Ran host-network UDP2Raw and forwarded to `127.0.0.1:<internal>`.

Observed issue:

- Speed still remained in the bad range.

Specific lessons:

- Docker loopback UDP publishing still puts the hot path through Docker forwarding.
- `127.0.0.1` in command lines is not enough; the namespace and forwarding mechanism matter.

### 9. Host-Network WG/AWG Plus Host-Network UDP2Raw

Shape:

- Moved both main WG/AWG container and UDP2Raw sidecar to host networking.
- Added host firewall, forwarding, NAT, and cleanup hooks.

Observed issues:

- App showed connected but internet still failed.
- `ping -c 3 1.1.1.1` timed out.
- `ping google.com` hung.
- Later diagnostics showed the client tunnel address as `10.8.1.1`, server peer allowed IP as `10.8.1.1/32`, server receiving packets but sending almost nothing back.

Specific lessons:

- Host networking alone does not make the implementation correct.
- WG/AWG addressing must be unambiguous. Client and server/gateway address handling must be validated.
- Packet counters must prove both ingress and return traffic. A recent handshake does not prove usable routing.

### 10. DNS Substitution, IP Forwarding, And Rule Prepending

Shape:

- Replaced Amnezia DNS for UDP2Raw configs.
- Added `net.ipv4.ip_forward=1`.
- Prepended iptables/NAT rules and removed stale duplicates.

Observed issue:

- These changes did not fix the user's no-internet symptom.

Specific lessons:

- These are necessary checks, but not sufficient proof.
- Do not continue patching isolated sysctls/rules without a packet-level hypothesis.

### 11. Client IP Allocation/Gateway Address Patch

Shape:

- Changed generated client IP allocation to avoid `.1`.
- Changed UDP2Raw server config to derive server interface `.1` from subnet `.0`.

Observed issue:

- The user still reported that it did not work.

Specific lessons:

- The observed `.1` peer was suspicious and should still be avoided, but it was not the whole issue.
- Do not rely on "recreate profile/container" as the only correctness mechanism.
- Future diagnostics must confirm the actual live client address and server peer address after install.

### 12. Qt Remote Objects / IPC Lifetime Patches

Shape:

- Several patches attempted to prevent service or GUI crashes in Qt Remote Objects and privileged process handling.

Observed issues:

- Some crashes changed shape or moved between service and GUI.
- Crash stacks included `QAbstractSocketPrivate::canReadNotification()`.

Specific lessons:

- IPC lifetime changes must be isolated and tested independently from UDP2Raw networking changes.
- Do not combine data-path topology rewrites with QtRO ownership/lifetime rewrites unless absolutely necessary.
- Privileged process wrappers must not delete socket-backed Qt objects synchronously while notifiers can still fire.

## Things To Avoid

- Do not assume Docker port publishing is acceptable for fake-TCP UDP2Raw without benchmark evidence.
- Do not assume Docker loopback publishing avoids Docker's hot path.
- Do not change UDP2Raw cipher/auth/socket-buffer defaults as a performance workaround.
- Do not add route exclusions for `127.0.0.1`.
- Do not kill local `udp2raw_mp` before the WG/AWG backend cleanup has actually completed or timed out.
- Do not emit disconnected before DNS, routes, PF/killswitch, peer cleanup, and interface cleanup have been attempted.
- Do not make the cleanup path all-or-nothing.
- Do not store DNS backups that can later restore Amnezia-managed DNS as the "original" system DNS.
- Do not rely on stale container/profile config after changing server-side address allocation.
- Do not treat `wg show latest handshake` as data-path success.
- Do not treat low rx bytes on the client as a cosmetic stats issue.
- Do not mix large topology changes, IPC lifetime changes, and UI state changes in one patch unless the failure evidence requires it.
- Do not ship without a server-side diagnostic that can show iptables/NAT counters moving during a client ping.

## Required Data-Path Invariants

The implementation must preserve these invariants:

- The public UDP2Raw listener accepts fake-TCP on the configured public port.
- The inner WG/AWG UDP listener is not publicly exposed except through UDP2Raw.
- The client WireGuard/AWG peer endpoint is rewritten to a local UDP2Raw listener only inside the runtime config.
- The real server IP remains available separately for route exclusion, status, and diagnostics.
- Server-side WG/AWG receives decrypted client packets.
- Server-side return packets are routed back through the same peer.
- NAT/forwarding rules have packet counters that move when the client pings an external IP.
- DNS resolvers used while connected are reachable through the chosen topology.
- Disconnect removes or neutralizes all tunnel-owned default/split routes, DNS settings, PF/killswitch state, and privileged child processes.

## Required Performance Invariants

- The server path must be close to the user's manual successful topology in the parts that matter for packet throughput.
- Any container boundary in the hot path must be explicitly justified and measured.
- Speed tests must be run with the default UDP2Raw cipher/auth/socket-buffer behavior unless the user approves otherwise.
- Throughput validation must be separated from DNS validation; use IP-based tests and domain-based tests.
- Jitter must be considered along with raw throughput.

## Required macOS Lifecycle Invariants

- `udp2raw_mp` must be owned by the privileged service or another clearly controlled privileged process path.
- If WG/AWG fails after UDP2Raw starts, UDP2Raw must be stopped.
- If UDP2Raw exits unexpectedly, WG/AWG must be stopped or marked failed; the app must not stay indefinitely in "Connecting".
- Backend `backendFailure` must be terminal from the user's perspective unless a retry is explicitly in progress.
- The app must surface a useful error state instead of hanging.
- Disconnect must be acknowledged or bounded by a timeout.
- A crash in the GUI must not leave root-owned tunnel processes, stale routes, stale DNS, or PF state behind.

## Required Test Coverage

Automated tests should cover:

- Container enum/string/default protocol mapping for UDP2Raw WG/AWG.
- JSON round-trip of UDP2Raw server and client fields.
- Runtime config rewrite keeps real remote host/port metadata while using localhost only for the inner endpoint.
- Route exclusion uses the real remote server, not `127.0.0.1`.
- Server scripts do not expose the inner WG/AWG UDP port publicly.
- Server scripts include required cleanup for any host-owned interfaces/processes they create.
- Disconnect path waits for or observes backend cleanup before tearing down dependent UDP2Raw process state.
- DNS substitution/restoration behavior for UDP2Raw does not leave Amnezia DNS behind after disconnect.
- Ping visibility remains functional when bytes stats are functional.

Manual tests must cover:

- UDP2Raw + WG connect and IP ping.
- UDP2Raw + WG domain lookup.
- UDP2Raw + WG browser traffic.
- UDP2Raw + AWG connect and IP ping.
- UDP2Raw + AWG domain lookup.
- UDP2Raw + AWG browser traffic.
- Disconnect after successful connection.
- Disconnect after failed/stuck connection.
- App crash or forced quit during connection, followed by normal internet check.
- Speed test with defaults.
- Jitter check with defaults.

## Acceptance Evidence

A future implementation is not acceptable until a test run provides:

- Client process list showing `udp2raw_mp` and the correct WG/AWG backend while connected.
- Client daemon status showing meaningful rx and tx growth, not only tx.
- Server `wg show` or `awg show` showing recent handshake and bidirectional transfer growth.
- Server NAT/FORWARD counters increasing for the tunnel subnet during `ping 1.1.1.1`.
- `ping -c 3 1.1.1.1` succeeds while connected.
- `ping -c 3 google.com` succeeds or fails quickly with a clear resolver error, never hangs indefinitely.
- Browser traffic works while connected.
- After disconnect, no UDP2Raw/WG/AWG process remains from the app.
- After disconnect, IPv4 default route points back to the physical network.
- After disconnect, DNS no longer points to an unreachable Amnezia-managed resolver.
- After disconnect, `route -n get google.com` returns.
- No new GUI or service crash report is created during disconnect.
- Speed is materially closer to the manual backend than to the 20-27 Mbps failed runs.

## Open Questions For The Next Design

These are not an implementation plan; they are unresolved design inputs that must be answered before coding:

- What exact server-side namespace and process topology matches the user's manual fast backend?
- Can the implementation avoid Docker in the UDP2Raw hot path while still fitting Amnezia's install/remove model?
- Which component should own server-side UDP2Raw lifecycle: protocol container, sidecar container, host service, or generated host script?
- How will server-side cleanup be made reliable if any interface or process lives in the host namespace?
- How will the implementation prove inner UDP is not publicly reachable?
- How will profile/container recreation avoid stale bad peers without requiring manual database edits?
- What is the minimal IPC change required, if any, for robust privileged process ownership?
- What should the app show when UDP2Raw starts but WG/AWG handshake or data-path validation fails?
