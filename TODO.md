# cgtun — open work

> Living backlog for this repository. Index: [`README.md`](README.md#future-work--backlog).

NAT traversal and optional DERP relay support. Endpoint trust stays with RODiT and the existing WireGuard/Noise handshake; URLs and TLS certificates are only for locating and protecting a relay host, not for mutual authentication between peers. Tailscale’s [`derper`](https://github.com/tailscale/tailscale/tree/main/cmd/derper) (BSD 3-Clause) can be run out of tree or leveraged with attribution without changing this project’s license.

## Open

- [ ] Separate transport from trust: abstract send/recv so WireGuard ciphertext can ride direct UDP or a relay path without changing RODiT/Noise auth
- [ ] Extend `Endpoint` beyond a single `SocketAddr` (candidates, active path, optional DERP region / home)
- [ ] STUN client and reflexive address discovery (e.g. against a `derper` STUN port or dedicated STUN)
- [ ] Candidate exchange over the RODiT-authenticated channel (local, reflexive, and relay hints; no peer PKI)
- [ ] NAT piercing / hole-punching loop with keepalives; prefer direct UDP as soon as a path works
- [ ] DERP client as bootstrap and fallback only (side channel while punching; relay if direct fails)
- [ ] Path selection: try direct first, fall back to DERP, upgrade to direct when piercing succeeds
- [ ] Discovery/config for relay map (RODiT metadata and/or DNS TXT); keep locator config separate from trust
- [ ] CLI / `DeviceConfig` flags for enabling DERP, map URL, and preferred region
- [ ] Event-loop support for TLS/TCP (or WebSocket) FDs alongside UDP/TUN (`epoll` / `kqueue`)
- [ ] Operate stock `derper` out of tree; document ports (TCP 80/443, UDP 3478) and that HTTP proxies / global LBs are unsuitable
- [ ] Optional relay abuse controls without Tailscale `--verify-clients` (RODiT-aware gate or private map); do not introduce client certificates for peer trust
- [ ] Integration tests for pierce success, DERP fallback, and upgrade-to-direct
- [ ] Document the NAT/DERP model in this README (trust vs reachability vs relay TLS)
