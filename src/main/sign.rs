//! FROST signer demo.
//!
//! This CLI does two things:
//!
//! - With the "-gen" argument, it generates a new Orchard address and Unified
//!   Full Viewing Key from a given `ak` (i.e. the FROST group public key
//!   generated elsewhere). Note that the UFVK includes a Sapling address, due
//!   to current zcash_client_backend limitations, but this demo only works for
//!   Orchard.
//! - Otherwise it will sign a transaction plan generated with Ywallet and write
//!   the signed transaction. It will prompt for the UFVK and will print a
//!   SIGHASH and a Randomizer, which are needed to generate a signature with
//!   rerandomized FROST. It will them prompt for the signature and write the
//!   signed transaction.
//!
//! Check the [FROST book](https://frost.zfnd.org/) for a complete tutorial
//! for the demo.
use std::fs;
use std::str::FromStr;

use clap::{Arg, Command};
use orchard::keys::{Scope, SpendValidatingKey};
use rand_chacha::rand_core::OsRng;
use warp_api_ffi::key2::decode_key;
use warp_api_ffi::note_selection::SecretKeys;
use warp_api_ffi::orchard::new_orchard_keys_for_ak;
use warp_api_ffi::{build_tx, TransactionPlan};
use zcash_client_backend::address::UnifiedAddress;
use zcash_client_backend::encoding::{
    decode_extended_full_viewing_key, decode_extended_spending_key,
};
use zcash_client_backend::keys::UnifiedFullViewingKey;
use zcash_params::coin::{get_coin_id, CoinType};
use zcash_primitives::consensus::{MainNetwork, Network, Parameters};

fn main() -> anyhow::Result<()> {
    let matches = Command::new("FROST Signer CLI")
        .version("1.0")
        .arg(
            Arg::new("tx_filename")
                .short('t')
                .long("tx")
                .takes_value(true),
        )
        .arg(
            Arg::new("out_filename")
                .short('o')
                .long("out")
                .takes_value(true),
        )
        .arg(Arg::new("gen").short('g').long("gen"))
        .get_matches();

    let (coin_type, network) = (CoinType::Zcash, Network::MainNetwork);

    let key = dotenv::var("KEY").unwrap();
    let index = u32::from_str(&dotenv::var("INDEX").unwrap_or_else(|_| "0".to_string())).unwrap();
    let coin = get_coin_id(coin_type);
    let (_seed, sk, fvk, _pa, _ofvk) = decode_key(coin, &key, index)?;

    let fvk =
        decode_extended_full_viewing_key(network.hrp_sapling_extended_full_viewing_key(), &fvk)
            .unwrap()
            .to_diversifiable_full_viewing_key();

    let sapling_sk = sk.unwrap();
    let sapling_sk =
        decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), &sapling_sk)
            .unwrap();

    if matches.is_present("gen") {
        let mut buffer = String::new();
        let stdin = std::io::stdin();
        println!("Input ak:");
        stdin.read_line(&mut buffer).unwrap();
        let ak = hex::decode(buffer.trim()).unwrap();
        let ak = SpendValidatingKey::from_bytes(&ak);

        let ofvk = new_orchard_keys_for_ak(network.coin_type(), index, ak.clone().unwrap());
        let a = ofvk.address_at(0u64, Scope::External);
        let orchard_address = UnifiedAddress::from_receivers(Some(a), None, None).unwrap();
        let orchard_address_str = orchard_address.encode(&MainNetwork);

        println!("Orchard address: {:?}", orchard_address_str);

        let ufvk = UnifiedFullViewingKey::new(Some(fvk), Some(ofvk.clone())).unwrap();
        let ufvk_str = ufvk.encode(&MainNetwork);
        println!("Unified Full Viewing Key: {:?}", ufvk_str);
        return Ok(());
    }

    let tx_filename = matches
        .value_of("tx_filename")
        .expect("input filename missing");
    let out_filename = matches
        .value_of("out_filename")
        .expect("output filename missing");

    let tx_plan = fs::read_to_string(tx_filename).expect("Should have been able to read the file");
    let tx_plan: TransactionPlan = serde_json::from_str(&tx_plan)?;

    let tx_plan_fvk = decode_extended_full_viewing_key(
        network.hrp_sapling_extended_full_viewing_key(),
        &tx_plan.fvk,
    )
    .unwrap()
    .to_diversifiable_full_viewing_key();

    if fvk.to_bytes() != tx_plan_fvk.to_bytes() {
        return Err(anyhow::anyhow!("Account does not match transaction"));
    }

    let mut ufvk_str = String::new();
    let stdin = std::io::stdin();
    println!("Input UFVK:");
    stdin.read_line(&mut ufvk_str).unwrap();
    let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, &ufvk_str.trim()).unwrap();

    let keys = SecretKeys {
        transparent: None,
        sapling: Some(sapling_sk),
        orchard: None,
    };

    let tx = build_tx(&network, &keys, &tx_plan, ufvk.orchard().cloned(), OsRng)?;

    fs::write(out_filename, base64::encode(&tx))?;

    println!("Tx written to {}", out_filename);
    Ok(())
}
