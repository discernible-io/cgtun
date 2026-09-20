// Copyright (c) 2023 Discernible IO. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use clap::{Arg, Command};
use cableguard::device::{DeviceConfig, DeviceHandle,ed2x_private_key_bytes,skx2pkx};
use cableguard::noise::Rodit;
use cableguard::device::api::{nearorg_rpc_tokens_for_owner,nearorg_rpc_state};
use cableguard::noise::constants::{SMART_CONTRACT,BLOCKCHAIN_NETWORK};
use cableguard::device::drop_privileges::drop_privileges;
// use daemonize::Daemonize;
use daemonize::{Daemonize, Outcome};
use base64::encode as base64encode;
use hex::{FromHex};
use serde_json::Value;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind,Read};
use std::env;
use tracing::{Level};

fn main() {
    let matches = Command::new("cableguard")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Discernible IO and Vlad Krasnov <vlad@cloudflare.com> et al, based on Wireguard (C) by Jason Donefeld")
        .args(&[
            // We input a NEAR Protocol json implicit account file as argument
            Arg::new("FILE_WITH_ACCOUNT")
                .required(true)
                .takes_value(true)
                .help("The full filename and path of the file with the NEAR.ORG blockchain implicit account"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .takes_value(true)
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .possible_values(["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1"),
                // CG: This probably needs to be tested and may be removed as tun devices are named and created internally
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .takes_value(true)
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/cableguard.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");

    // Enable for tracing in main
    /*
    let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::TRACE)
    .finish();
    tracing::subscriber::set_global_default(subscriber)
    .expect("Error: Failed to set subscriber");
    */

    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = matches.value_of_t("uapi-fd").unwrap_or_else(|e| e.exit());
    let n_threads: usize = matches.value_of_t("threads").unwrap_or_else(|e| e.exit());
    let log_level: Level = matches.value_of_t("verbosity").unwrap_or_else(|e| e.exit());

    // Obtain the public key from the file with the accountId
    let accountfile_name = matches.value_of("FILE_WITH_ACCOUNT").unwrap();
    let accountfile_path = accountfile_name;
    let mut accountfile = match File::open(&accountfile_path) {
        Ok(accountfile) => accountfile,
        Err(err) => {
            println!("Error: Failed to open the file with the accountId: {}", err);
            return; // Terminate the program or handle the Error accordingly
        }
    };

    let mut accountfile_contents = String::new();
    if let Err(err) = accountfile.read_to_string(&mut accountfile_contents) {
        println!("Error: Failed to read the file with the accountId: {}", err);
        return; // Terminate the program or handle the Error accordingly
    }

    let json: Value = match serde_json::from_str(&accountfile_contents) {
        Ok(contents) => contents,
        Err(err) => {
            println!("Error: Failed to parse JSON of the file with the accountId: {}", err);
            // Add any additional Error handling logic if needed
            return; // Terminate the program
        }
    };

    // Obtain the value of the "account_id" field, include it in a json string
    let account_id = json["implicit_account_id"].as_str().expect("Error: Invalid account_id value");

    // Obtain the value of the "private_key" field, include it in a json string and encode it as Base58
    let own_static_base58_private_ed25519_key = json["private_key"].as_str().expect("Error: Invalid Private_key value");
    let own_static_base58_private_ed25519_key = own_static_base58_private_ed25519_key.trim_start_matches("ed25519:");

    // Initialize a RODiT object
    let rodt: Rodit;

    tracing::trace!("Info: Smart Contract Account: {}", SMART_CONTRACT);

    // Perform a RPC call with it and obtain the token_id
    match nearorg_rpc_state(BLOCKCHAIN_NETWORK, SMART_CONTRACT, account_id) {
        Ok(result) => { result
        }
        Err(err) => {
            println!("Error: The NEAR account has no balance in {}, {}", BLOCKCHAIN_NETWORK, err);
            std::process::exit(1);
        }
    }

    // Retrieve from the blockchain the Own RODiT using the account_id, not the token_id
    let account_idargs = "{\"account_id\":\"".to_owned() + account_id + "\",\"from_index\":0,\"limit\":1}";
    match nearorg_rpc_tokens_for_owner(BLOCKCHAIN_NETWORK, SMART_CONTRACT, SMART_CONTRACT, "nft_tokens_for_owner", &account_idargs) {
        Ok(result) => {
            rodt = result;
        }
        Err(err) => {
            // Handle the Error
            println!("Error: There is no Own RODiT associated with the account: {}", err);
            std::process::exit(1);
        }
    }

    // Create an Interface Name derived from the token_id ULID,
    // with a max length of 15 characters, by default utun+last 11 of ULID for operating systems compatibility,
    let tun_name = format!("utun{}", &rodt.token_id[rodt.token_id.len() - 11..]).to_lowercase();

    // We decode it to Hex format Private Key Ed25519 of 64 bytes
    let own_static_bytes_private_ed25519_key = bs58::decode(own_static_base58_private_ed25519_key)
        .into_vec()
        .expect("Error: Failed to decode the private key from Base58");
    assert_eq!(own_static_bytes_private_ed25519_key.len(), 64);

    // Create a X25519 private key from a Private Key Ed25519 of 64 bytes
    let own_staticsecret_private_x25519_key = ed2x_private_key_bytes(own_static_bytes_private_ed25519_key.clone().try_into().unwrap());
    let own_static_bytes_private_x25519_key = own_staticsecret_private_x25519_key.as_bytes();

    // Generate the X25519 public key from the X25519 private key of 32 bytes
    let own_static_bytes_public_x25519_key = skx2pkx(own_staticsecret_private_x25519_key.clone());
    // let own_static_b64_public_x25519_key = hex_to_base64(&own_static_bytes_public_x25519_key);

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    tracing::trace!("Info: To create or display available RODiT Blockchain Directory accounts use: \"rodtwallet.sh\"");

    if background {
        // Running in background mode
        let log = matches.value_of("log").unwrap();

        // Check if the log file exists, open it in append mode if it does
        // Otherwise, create a new log file
        let log_file = if let Ok(metadata) = std::fs::metadata(&log) {
            if metadata.is_file() {
                OpenOptions::new().append(true).open(&log)
            } else {
                Err(io::Error::new(
                    ErrorKind::Other,
                    format!("{} is not a regular file.", log),
                ))
            }
        } else {
            File::create(&log)
        }
        .unwrap_or_else(|err| panic!("Error: Failed to open log file {}: {}", log, err));

        // Create a non-blocking log writer and get a guard to prevent dropping it
        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);
        _guard = guard;

        // Initialize the logging system with the configured log level and writer
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        // daemonize 0.5.0 version
            // Create a daemon process and configure it
            let daemonize = Daemonize::new().working_directory("/tmp");
            match daemonize.execute() {
                Outcome::Parent(Ok(_)) => {
                    // In parent process, child forked ok
                    let mut b = [0u8; 1];
                    if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                        println!("Info: Discernible IO started successfully");
                        exit(0);
                    } else {
                         println!("Error: Discernible IO Failed to start. Check if the capabilities are set and you are running with enough privileges.");
                        exit(1);
                    }
                }
                Outcome::Parent(Err(_e)) => {
                    println!("Error: Discernible IO Failed to start. Check if the capabilities are set and you are running with enough privileges.");
                    exit(1);
                 }
                Outcome::Child(_) => {
                    // In child process, we'll continue below with code that is common with foreground exec
                    println!("Info: Discernible IO started successfully");
                }
            }

    } else {
        // Running in foreground mode
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let mut own_bytes_ed25519_private_key: [u8; 64] = [0; 64];
    own_bytes_ed25519_private_key.copy_from_slice(&own_static_bytes_private_ed25519_key[..64]);

    // Configure the device with the Own RODiT and the keys
    let config = DeviceConfig {
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
        rodt,
        own_bytes_ed25519_private_key,
        x25519_private_key: *own_static_bytes_private_x25519_key,
        x25519_public_key: own_static_bytes_public_x25519_key,
    };

    // Initialize the device handle with the specified tunnel name and configuration
    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, &config) {
        Ok(d) => d,
        Err(e) => {
            // Failed to notify parent problem with tunnel initiation
            tracing::trace!(message = "Error: Failed to initialize tunnel. Check if you are running with sudo", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        // Drop privileges if not disabled
        if let Err(e) = drop_privileges() {
            tracing::trace!(message = "Error: Failed to drop privileges", error = ?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initiation success
    sock1.send(&[1]).unwrap();
    drop(sock1);

    println!("Info: Discernible IO will hand over to TUN handle");

    // Wait for the device handle to finish processing
    device_handle.wait();
}

fn hex_to_base64(hex_bytes: &[u8; 32]) -> String {
    let hex_string = hex_bytes.iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<String>>()
        .join("");

    let bytes = Vec::from_hex(&hex_string).expect("Error: Invalid Hex string");
    base64encode(&bytes)
}
