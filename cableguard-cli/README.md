![Discernible IO logo banner](./banner.png)

# Discernible IO TUN

**Discernible IO TUN** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol with Rich Online Digital Tokens (RODiT). RODiT are an implementation of non-fungible tokens that contain all the configuration, identity, and subscription information for Discernible IO TUN endpoints. Discernible IO TUN is based on Cloudflare's Borintung, a Rust implememtation of Wireguard.
This project is part of a large ecosystem (Discernible IO FORGE, Discernible IO TOOL, Discernible IO WALLET, Discernible IO FIND and Discernible IO AUTH), and consists of three parts:

* The executable `cableguard-cli`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) implementation for Linux and macOS.
* The library `cableguard` that implements the underlying WireGuard protocol, without the network or tunnel stacks that need to be that need to be implemented in a platform idiomatic way.
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
- cargo build --bin cableguard-cli --release
By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin cableguard --path .`.

You may want to add to .bashrc these lines:
- sudo setcap cap_net_admin+epi ./<path>/cableguard-cli
- export BLOCKCHAIN_ENV=testnet (for testnet, mainnet for mainnet)

## How to Install from .deb package
wget https://cableguard.fra1.digitaloceanspaces.com/cableguard-cli_0.89.99_amd64.deb
sudo apt install ./cableguard-cli_0.92.58_amd64.deb

## How to Use
To start a tunnel use:
`cableguard-cli [-f/--foreground] <filewithaccount.json>`

Where <filewithaccount.json> is a NEAR implicit account created with ./wallet/rodtwallet.sh genaccount

`cableguard` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.
You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi cableguard`.

It may be possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `cableguard`. For example:
`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=cableguard-cli WG_SUDO=1 wg-quick up CONFIGURATION`

## Supported platforms
- It has only been tested in AMD/Intel
- `x86-64` architecture is supported.

# Discernible IO Ecosystem
- Discernible IO RODIVPN: RODiT and VPN manager
- Discernible IO TOOLS: local VPN tunnel configuration
- Discernible IO TUN: VPN tunnels
- Discernible IO FORGE: RODiT minter

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. Discernible IO is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
