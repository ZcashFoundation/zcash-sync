//! Payments

use anyhow::anyhow;
use std::str::FromStr;

use secp256k1::SecretKey;

use crate::api::sync::get_latest_height;
use crate::coinconfig::{get_prover, CoinConfig};
use crate::pay::TxBuilder;
pub use crate::{broadcast_tx, Tx};
use zcash_client_backend::encoding::{
    decode_extended_full_viewing_key, decode_extended_spending_key,
};
use zcash_primitives::consensus::Parameters;
use zcash_primitives::transaction::builder::Progress;

use crate::db::{AccountData, ZMessage};
use crate::taddr::get_utxos;
use serde::Deserialize;
use zcash_primitives::memo::Memo;
// use crate::wallet::Recipient;

type PaymentProgressCallback = Box<dyn Fn(Progress) + Send + Sync>;

async fn prepare_multi_payment(
    last_height: u32,
    recipients: &[RecipientMemo],
    use_transparent: bool,
    anchor_offset: u32,
) -> anyhow::Result<(Tx, Vec<u32>)> {
    // let c = CoinConfig::get_active();
    // let mut tx_builder = TxBuilder::new(c.coin_type, last_height);
    //
    // let AccountData { fvk, .. } = c.db()?.get_account_info(c.id_account)?;
    // let fvk = decode_extended_full_viewing_key(
    //     c.chain.network().hrp_sapling_extended_full_viewing_key(),
    //     &fvk,
    // )
    // .unwrap();
    // let utxos = if use_transparent {
    //     let mut client = c.connect_lwd().await?;
    //     let t_address = c.db()?.get_taddr(c.id_account)?;
    //     if let Some(t_address) = t_address {
    //         get_utxos(&mut client, &t_address, c.id_account).await?
    //     } else {
    //         vec![]
    //     }
    // } else {
    //     vec![]
    // };
    //
    // let target_amount: u64 = recipients.iter().map(|r| r.amount).sum();
    // let anchor_height = last_height.saturating_sub(anchor_offset);
    // let spendable_notes = c
    //     .db()?
    //     .get_spendable_notes(c.id_account, anchor_height, &fvk)?;
    // let note_ids = tx_builder.select_inputs(&fvk, &spendable_notes, &utxos, target_amount)?;
    // tx_builder.select_outputs(&fvk, recipients)?;
    // Ok((tx_builder.tx, note_ids))
    todo!()
}

fn sign(tx: &Tx, progress_callback: PaymentProgressCallback) -> anyhow::Result<Vec<u8>> {
    // let c = CoinConfig::get_active();
    // let prover = get_prover();
    // let db = c.db()?;
    // let AccountData { sk: zsk, .. } = db.get_account_info(c.id_account)?;
    // let zsk = zsk.ok_or(anyhow!("Cannot sign without secret key"))?;
    // let tsk = db
    //     .get_tsk(c.id_account)?
    //     .map(|tsk| SecretKey::from_str(&tsk).unwrap());
    // let extsk =
    //     decode_extended_spending_key(c.chain.network().hrp_sapling_extended_spending_key(), &zsk)
    //         .unwrap();
    // let raw_tx = tx.sign(tsk, &extsk, prover, progress_callback)?;
    // Ok(raw_tx)
    todo!()
}

/// Build a multi payment for offline signing
/// # Arguments
/// * `last_height`: current block height
/// * `recipients`: list of recipients
/// * `use_transparent`: include transparent balance
/// * `anchor_offset`: minimum number of confirmations for note selection
pub async fn build_only_multi_payment(
    last_height: u32,
    recipients: &[RecipientMemo],
    use_transparent: bool,
    anchor_offset: u32,
) -> anyhow::Result<Tx> {
    let (tx, _) =
        prepare_multi_payment(last_height, recipients, use_transparent, anchor_offset).await?;
    // let tx_str = serde_json::to_string(&tx)?;
    Ok(tx)
}

/// Sign a transaction
/// # Arguments
/// * `tx`: transaction to sign
/// * `progress_callback`: function callback during transaction building
pub async fn sign_only_multi_payment(
    tx: &Tx,
    progress_callback: PaymentProgressCallback,
) -> anyhow::Result<Vec<u8>> {
    // let tx = serde_json::from_str::<Tx>(tx_string)?;
    let raw_tx = sign(tx, progress_callback)?;
    Ok(raw_tx)
}

/// Build, sign and broadcast a multi payment
/// # Arguments
/// * `last_height`: current block height
/// * `recipients`: list of recipients
/// * `use_transparent`: include transparent balance
/// * `anchor_offset`: minimum number of confirmations for note selection
/// * `progress_callback`: function callback during transaction building
pub async fn build_sign_send_multi_payment(
    last_height: u32,
    recipients: &[RecipientMemo],
    use_transparent: bool,
    anchor_offset: u32,
    progress_callback: PaymentProgressCallback,
) -> anyhow::Result<String> {
    let c = CoinConfig::get_active();
    let (tx, note_ids) =
        prepare_multi_payment(last_height, recipients, use_transparent, anchor_offset).await?;
    let raw_tx = sign(&tx, progress_callback)?;
    let tx_id = broadcast_tx(&raw_tx).await?;

    c.db()?.tx_mark_spend(&note_ids)?;
    let mut mempool = c.mempool.lock().unwrap();
    mempool.clear()?;
    Ok(tx_id)
}

/// Make a transaction that shields the transparent balance
pub async fn shield_taddr() -> anyhow::Result<String> {
    let last_height = get_latest_height().await?;
    let tx_id = build_sign_send_multi_payment(last_height, &[], true, 0, Box::new(|_| {})).await?;
    Ok(tx_id)
}

/// Parse a json document that contains a list of recipients
pub fn parse_recipients(recipients: &str) -> anyhow::Result<Vec<RecipientMemo>> {
    let c = CoinConfig::get_active();
    let AccountData { address, .. } = c.db()?.get_account_info(c.id_account)?;
    let recipients: Vec<Recipient> = serde_json::from_str(recipients)?;
    let recipient_memos: Vec<_> = recipients
        .iter()
        .map(|r| RecipientMemo::from_recipient(&address, r))
        .collect();
    Ok(recipient_memos)
}

/// Encode a message into a memo
pub fn encode_memo(from: &str, include_from: bool, subject: &str, body: &str) -> String {
    let from = if include_from { from } else { "" };
    let msg = format!("\u{1F6E1}MSG\n{}\n{}\n{}", from, subject, body);
    msg
}

/// Decode a memo into a message
pub fn decode_memo(
    id_tx: u32,
    memo: &str,
    recipient: &str,
    timestamp: u32,
    height: u32,
) -> ZMessage {
    let memo_lines: Vec<_> = memo.splitn(4, '\n').collect();
    let msg = if memo_lines[0] == "\u{1F6E1}MSG" {
        ZMessage {
            id_tx,
            sender: if memo_lines[1].is_empty() {
                None
            } else {
                Some(memo_lines[1].to_string())
            },
            recipient: recipient.to_string(),
            subject: memo_lines[2].to_string(),
            body: memo_lines[3].to_string(),
            timestamp,
            height,
        }
    } else {
        ZMessage {
            id_tx,
            sender: None,
            recipient: recipient.to_string(),
            subject: memo_lines[0].chars().take(20).collect(),
            body: memo.to_string(),
            timestamp,
            height,
        }
    };
    msg
}

#[derive(Deserialize)]
pub struct Recipient {
    pub address: String,
    pub amount: u64,
    pub reply_to: bool,
    pub subject: String,
    pub memo: String,
    pub max_amount_per_note: u64,
}

#[derive(Clone, Deserialize)]
pub struct RecipientShort {
    pub address: String,
    pub amount: u64,
}

pub struct RecipientMemo {
    pub address: String,
    pub amount: u64,
    pub memo: Memo,
    pub max_amount_per_note: u64,
}

impl RecipientMemo {
    pub fn from_recipient(from: &str, r: &Recipient) -> Self {
        let memo = if !r.reply_to && r.subject.is_empty() {
            r.memo.clone()
        } else {
            encode_memo(from, r.reply_to, &r.subject, &r.memo)
        };
        RecipientMemo {
            address: r.address.clone(),
            amount: r.amount,
            memo: Memo::from_str(&memo).unwrap(),
            max_amount_per_note: r.max_amount_per_note,
        }
    }
}

impl From<RecipientShort> for RecipientMemo {
    fn from(r: RecipientShort) -> Self {
        RecipientMemo {
            address: r.address,
            amount: r.amount,
            memo: Memo::Empty,
            max_amount_per_note: 0,
        }
    }
}
