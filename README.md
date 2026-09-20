![Discernible IO logo banner](./banner.png)

# Discernible IO TUN

**Discernible IO TUN** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol with Rich Online Digital Tokens (RODiT). RODiT are an implementation of non-fungible tokens that contain all the configuration, identity, and subscription information for Discernible IO TUN endpoints. Discernible IO TUN is based on Cloudflare's Borintung, a Rust implememtation of Wireguard.
This project is part of a large ecosystem (Discernible IO FORGE, Discernible IO TOOL, Discernible IO WALLET, Discernible IO FIND and Discernible IO AUTH), and consists of three parts:

* The executable `discernible-vpn`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) implementation for Linux and macOS.
* The library `discernible-vpn` that implements the underlying WireGuard protocol, without the network or tunnel stacks that need to be that need to be implemented in a platform idiomatic way.
* The rodtwallet.sh scripts (temporary implementation of Discernible IO WALLET) that works with the NEAR CLI interface. It provides barebones command line crytographic commands for the management of RODiT and NEAR implicit accounts.

## License
This project is released under the [GPLv2](COPYING).
More information may be found at [WireGuard.com](https://www.wireguard.com/).**

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please contact Discernible IO.

## How to Install from Source
- sudo apt install pkg-config
- git clone https://github.com/discernible-io/cgtun.git
- cargo build --bin discernible-vpn --release
By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin discernible-vpn --path .`.

You may want to add to .bashrc these lines:
- sudo setcap cap_net_admin+epi ./<path>/discernible-vpn
- export BLOCKCHAIN_ENV=testnet (for testnet, mainnet for mainnet)

## How to Install from .deb package
wget https://discernible-vpn.fra1.digitaloceanspaces.com/discernible-vpn_0.89.99_amd64.deb
sudo apt install ./discernible-vpn_0.92.58_amd64.deb

## How to Use
To start a tunnel use:
`discernible-vpn [-f/--foreground] <filewithaccount.json>`

Where <filewithaccount.json> is a NEAR implicit account created with ./wallet/rodtwallet.sh genaccount

`discernible-vpn` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.
You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi discernible-vpn`.

It may be possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `discernible-vpn`. For example:
`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=discernible-vpn WG_SUDO=1 wg-quick up CONFIGURATION`

## Supported platforms
- It has only been tested in AMD/Intel
- `x86-64` architecture is supported.

## Future work

NAT traversal and optional DERP relay support. Endpoint trust stays with RODiT and the existing WireGuard/Noise handshake; URLs and TLS certificates are only for locating and protecting a relay host, not for mutual authentication between peers. Tailscale’s [`derper`](https://github.com/tailscale/tailscale/tree/main/cmd/derper) (BSD 3-Clause) can be run out of tree or leveraged with attribution without changing this project’s license.

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

# Discernible IO Ecosystem
- Discernible IO RODITVPN: RODiT and VPN manager
- Discernible IO TOOLS: local VPN tunnel configuration
- Discernible IO TUN: VPN tunnels
- Discernible IO FORGE: RODiT minter

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. Discernible IO is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
