use std::fs;
use std::str::FromStr;

use clap::{Arg, Command};
use orchard::keys::SpendingKey;
use rand_chacha::rand_core::OsRng;
use secp256k1::SecretKey;
use warp_api_ffi::note_selection::SecretKeys;
use warp_api_ffi::orchard::derive_orchard_keys;
use warp_api_ffi::{build_tx, TransactionPlan};
use warp_api_ffi::{key2::decode_key, taddr::derive_tkeys};
use zcash_client_backend::encoding::{
    decode_extended_full_viewing_key, decode_extended_spending_key,
};
use zcash_params::coin::{get_coin_id, CoinType};
use zcash_primitives::consensus::{Network, Parameters};

fn main() -> anyhow::Result<()> {
    let matches = Command::new("Cold wallet Signer CLI")
        .version("1.0")
        .arg(Arg::new("coin").short('c').long("coin").takes_value(true))
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
        .get_matches();

    let coin = matches.value_of("coin").expect("coin argument missing");
    let tx_filename = matches
        .value_of("tx_filename")
        .expect("input filename missing");
    let out_filename = matches
        .value_of("out_filename")
        .expect("output filename missing");

    let tx_plan = fs::read_to_string(tx_filename).expect("Should have been able to read the file");
    let tx_plan: TransactionPlan = serde_json::from_str(&tx_plan)?;

    let (coin_type, network) = match coin {
        "zcash" => (CoinType::Zcash, Network::MainNetwork),
        "ycash" => (CoinType::Ycash, Network::YCashMainNetwork),
        _ => panic!("Invalid coin"),
    };
    let key = dotenv::var("KEY").unwrap();
    let index = u32::from_str(&dotenv::var("INDEX").unwrap_or_else(|_| "0".to_string())).unwrap();
    let coin = get_coin_id(coin_type);
    let (seed, sk, fvk, _pa, _ofvk) = decode_key(coin, &key, index)?;
    let seed = seed.unwrap();

    let fvk =
        decode_extended_full_viewing_key(network.hrp_sapling_extended_full_viewing_key(), &fvk)
            .unwrap()
            .to_diversifiable_full_viewing_key();
    let tx_plan_fvk = decode_extended_full_viewing_key(
        network.hrp_sapling_extended_full_viewing_key(),
        &tx_plan.fvk,
    )
    .unwrap()
    .to_diversifiable_full_viewing_key();

    if fvk.to_bytes() != tx_plan_fvk.to_bytes() {
        return Err(anyhow::anyhow!("Account does not match transaction"));
    }

    let bip44_path = format!("m/44'/{}'/0'/0/{}", network.coin_type(), index);
    let (tsk, _address) = derive_tkeys(&network, &seed, &bip44_path)?;
    let transparent_sk = SecretKey::from_str(&tsk).unwrap();

    let sapling_sk = sk.unwrap();
    let sapling_sk =
        decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), &sapling_sk)
            .unwrap();

    let ob = derive_orchard_keys(network.coin_type(), &seed, index);
    let orchard_sk = ob.sk.map(|sk| SpendingKey::from_bytes(sk).unwrap());

    let keys = SecretKeys {
        transparent: Some(transparent_sk),
        sapling: Some(sapling_sk),
        orchard: orchard_sk,
    };

    let tx = build_tx(&network, &keys, &tx_plan, false, OsRng)?;

    fs::write(out_filename, base64::encode(&tx))?;

    println!("Tx written to {}", out_filename);
    Ok(())
}
