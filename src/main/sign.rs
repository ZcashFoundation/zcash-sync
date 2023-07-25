use std::fs;
use std::str::FromStr;

use clap::{Arg, Command};
use orchard::keys::{FullViewingKey, Scope, SpendValidatingKey, SpendingKey};
use rand_chacha::rand_core::OsRng;
use secp256k1::SecretKey;
use warp_api_ffi::note_selection::SecretKeys;
use warp_api_ffi::orchard::{derive_orchard_keys, new_orchard_keys_for_ak};
use warp_api_ffi::{build_tx, TransactionPlan};
use warp_api_ffi::{key2::decode_key, taddr::derive_tkeys};
use zcash_client_backend::address::UnifiedAddress;
use zcash_client_backend::encoding::{
    decode_extended_full_viewing_key, decode_extended_spending_key,
};
use zcash_client_backend::keys::UnifiedFullViewingKey;
use zcash_params::coin::{get_coin_id, CoinType};
use zcash_primitives::consensus::{MainNetwork, Network, Parameters};

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
        .arg(Arg::new("gen").short('g').long("gen"))
        .get_matches();

    let coin = matches.value_of("coin").expect("coin argument missing");

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

    let bip44_path = format!("m/44'/{}'/0'/0/{}", network.coin_type(), index);
    let (tsk, _address) = derive_tkeys(&network, &seed, &bip44_path)?;
    let transparent_sk = SecretKey::from_str(&tsk).unwrap();

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
    // let ufvk_str = "uview1kahs7mgjuarpeuzxnp6ktxjpu2d4uksgf9v05kck27el8v4edfzjfdpvxv7fw95xkf8cfq9nh4sthqu8ncs5sl024cc2e63qxtwx2qqzdrqvd4py42ng547eje0v0sqpr7vu77ywsq8wfty6aev4m48g83yuclppd7musyms87wunmkpps2rr0frmyc58ajyckulwlwnad3jkthp5f738c02n5kkg5vy7q8xm6npfdgc9x9emwpxnear09wx36qrk55q8f2x93zgeem8mjsj8h3ksueg6rj7me36kx03q4dax4kzltr964tygfpsuzchh34xzcwg52njt38etrwpjmnfft8xskgdmardnvlnwlv7t7pzc00zjhhl28q2dfkr2ylsyeq9znay6";
    let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, &ufvk_str.trim()).unwrap();

    let keys = SecretKeys {
        transparent: Some(transparent_sk),
        sapling: Some(sapling_sk),
        orchard: None,
    };

    let tx = build_tx(&network, &keys, &tx_plan, ufvk.orchard().cloned(), OsRng)?;

    fs::write(out_filename, base64::encode(&tx))?;

    println!("Tx written to {}", out_filename);
    Ok(())
}
