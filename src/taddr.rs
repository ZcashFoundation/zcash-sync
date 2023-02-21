use crate::api::payment_v2::build_tx_plan_with_utxos;
use crate::api::recipient::RecipientMemo;
use crate::chain::{get_checkpoint_height, EXPIRY_HEIGHT_OFFSET};
use crate::coinconfig::CoinConfig;
use crate::db::AccountData;
use crate::note_selection::{SecretKeys, Source, UTXO};
use crate::unified::orchard_as_unified;
use crate::{
    broadcast_tx, build_tx, AddressList, CompactTxStreamerClient, GetAddressUtxosArg,
    GetAddressUtxosReply, TransparentAddressBlockFilter,
};
use anyhow::anyhow;
use base58check::FromBase58Check;
use bip39::{Language, Mnemonic, Seed};
use core::slice;
use futures::StreamExt;
use rand::rngs::OsRng;
use ripemd::{Digest, Ripemd160};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use tiny_hderive::bip32::ExtendedPrivKey;
use tonic::transport::Channel;
use tonic::Request;
use zcash_client_backend::encoding::encode_transparent_address;
use zcash_primitives::consensus::{Network, Parameters};
use zcash_primitives::legacy::TransparentAddress;
use zcash_primitives::memo::Memo;

pub async fn get_taddr_balance(
    client: &mut CompactTxStreamerClient<Channel>,
    address: &str,
) -> anyhow::Result<u64> {
    let req = AddressList {
        addresses: vec![address.to_string()],
    };
    let rep = client
        .get_taddress_balance(Request::new(req))
        .await?
        .into_inner();
    Ok(rep.value_zat as u64)
}

pub async fn get_taddr_tx_count(
    client: &mut CompactTxStreamerClient<Channel>,
    address: &str,
) -> anyhow::Result<u32> {
    let req = TransparentAddressBlockFilter {
        address: address.to_string(),
        range: None,
    };
    let rep = client
        .get_taddress_txids(Request::new(req))
        .await?
        .into_inner();
    let count = rep.count().await;
    Ok(count as u32)
}

pub async fn get_utxos(
    client: &mut CompactTxStreamerClient<Channel>,
    t_address: &str,
) -> anyhow::Result<Vec<GetAddressUtxosReply>> {
    let req = GetAddressUtxosArg {
        addresses: vec![t_address.to_string()],
        start_height: 0,
        max_entries: 0,
    };
    let utxo_rep = client
        .get_address_utxos(Request::new(req))
        .await?
        .into_inner();
    Ok(utxo_rep.address_utxos)
}

pub async fn scan_transparent_accounts(
    network: &Network,
    client: &mut CompactTxStreamerClient<Channel>,
    gap_limit: usize,
) -> anyhow::Result<Vec<TBalance>> {
    let c = CoinConfig::get_active();
    let mut addresses = vec![];
    let db = c.db()?;
    let account_data = db.get_account_info(c.id_account)?;
    let AccountData {
        seed, mut aindex, ..
    } = account_data;
    if let Some(seed) = seed {
        let mut gap = 0;
        while gap < gap_limit {
            let bip44_path = format!("m/44'/{}'/0'/0/{}", network.coin_type(), aindex);
            log::info!("{} {}", aindex, bip44_path);
            let (_, address) = derive_tkeys(network, &seed, &bip44_path)?;
            let balance = get_taddr_balance(client, &address).await?;
            if balance > 0 {
                addresses.push(TBalance {
                    index: aindex,
                    address,
                    balance,
                });
                gap = 0;
            } else {
                let tx_count = get_taddr_tx_count(client, &address).await?;
                if tx_count != 0 {
                    gap = 0;
                } else {
                    gap += 1;
                }
            }
            aindex += 1;
        }
    }
    Ok(addresses)
}

pub fn derive_tkeys(
    network: &Network,
    phrase: &str,
    path: &str,
) -> anyhow::Result<(String, String)> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    let seed = Seed::new(&mnemonic, "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), path)
        .map_err(|_| anyhow!("Invalid derivation path"))?;
    let secret_key = SecretKey::from_slice(&ext.secret())?;
    derive_from_secretkey(network, &secret_key)
}

pub fn parse_seckey(key: &str) -> anyhow::Result<SecretKey> {
    let (_, sk) = key.from_base58check().map_err(|_| anyhow!("Invalid key"))?;
    let sk = &sk[0..sk.len() - 1]; // remove compressed pub key marker
    let secret_key = SecretKey::from_slice(&sk)?;
    Ok(secret_key)
}

pub fn derive_taddr(network: &Network, key: &str) -> anyhow::Result<(SecretKey, String)> {
    let secret_key = parse_seckey(key)?;
    let (_, addr) = derive_from_secretkey(network, &secret_key)?;
    Ok((secret_key, addr))
}

pub fn derive_from_secretkey(
    network: &Network,
    sk: &SecretKey,
) -> anyhow::Result<(String, String)> {
    let secp = Secp256k1::<All>::new();
    let pub_key = PublicKey::from_secret_key(&secp, &sk);
    let pub_key = pub_key.serialize();
    let pub_key = Ripemd160::digest(&Sha256::digest(&pub_key));
    let address = TransparentAddress::PublicKey(pub_key.into());
    let address = encode_transparent_address(
        &network.b58_pubkey_address_prefix(),
        &network.b58_script_address_prefix(),
        &address,
    );
    let sk = sk.display_secret().to_string();
    Ok((sk, address))
}

pub async fn sweep_tkey(
    last_height: u32,
    sk: &str,
    pool: u8,
    confirmations: u32,
) -> anyhow::Result<String> {
    let c = CoinConfig::get_active();
    let network = c.chain.network();
    let (seckey, from_address) = derive_taddr(network, sk)?;

    let (checkpoint_height, to_address) = {
        let db = c.db().unwrap();
        let checkpoint_height = get_checkpoint_height(&db, last_height, confirmations)?;

        let to_address = match pool {
            0 => db.get_taddr(c.id_account)?,
            1 => {
                let AccountData { address, .. } = db.get_account_info(c.id_account)?;
                Some(address)
            }
            2 => {
                let okeys = db.get_orchard(c.id_account)?;
                okeys.map(|okeys| {
                    let address = okeys.get_address(0);
                    orchard_as_unified(network, &address).encode()
                })
            }
            _ => unreachable!(),
        };
        let to_address = to_address.ok_or(anyhow!("Account has no address of this type"))?;
        (checkpoint_height, to_address)
    };

    let mut client = c.connect_lwd().await?;
    let utxos = get_utxos(&mut client, &from_address).await?;
    let balance = utxos.iter().map(|utxo| utxo.value_zat).sum::<i64>();
    println!("balance {}", balance);
    let utxos: Vec<_> = utxos
        .iter()
        .enumerate()
        .map(|(i, utxo)| UTXO {
            id: i as u32,
            source: Source::Transparent {
                txid: utxo.txid.clone().try_into().unwrap(),
                index: utxo.index as u32,
            },
            amount: utxo.value_zat as u64,
        })
        .collect();
    let recipient = RecipientMemo {
        address: to_address,
        amount: balance as u64,
        fee_included: true,
        memo: Memo::default(),
        max_amount_per_note: 0,
    };
    println!("build_tx_plan_with_utxos");
    let tx_plan = build_tx_plan_with_utxos(
        c.coin,
        c.id_account,
        checkpoint_height,
        last_height + EXPIRY_HEIGHT_OFFSET,
        slice::from_ref(&recipient),
        &utxos,
    )
    .await?;
    let skeys = SecretKeys {
        transparent: Some(seckey),
        sapling: None,
        orchard: None,
    };
    println!("build_tx");
    let tx = build_tx(network, &skeys, &tx_plan, OsRng)?;
    println!("broadcast_tx");
    let txid = broadcast_tx(&tx).await?;
    Ok(txid)
}

pub struct TBalance {
    pub index: u32,
    pub address: String,
    pub balance: u64,
}
