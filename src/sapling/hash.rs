use ff::PrimeField;
use group::Curve;
use jubjub::{ExtendedPoint, Fr};
use zcash_primitives::constants::PEDERSEN_HASH_CHUNKS_PER_GENERATOR;
use crate::sync::{Hasher, Node};
use super::GENERATORS_EXP;

#[inline(always)]
fn accumulate_scalar(acc: &mut Fr, cur: &mut Fr, x: u8) {
    let mut tmp = *cur;
    if x & 1 != 0 {
        tmp += *cur;
    }
    *cur = cur.double();
    if x & 2 != 0 {
        tmp += *cur;
    }
    if x & 4 != 0 {
        tmp = tmp.neg();
    }

    *acc += tmp;
}

fn accumulate_generator(acc: &Fr, idx_generator: u32) -> ExtendedPoint {
    let acc_bytes = acc.to_repr();

    let mut tmp = ExtendedPoint::identity();
    for (i, &j) in acc_bytes.iter().enumerate() {
        let offset = (idx_generator * 32 + i as u32) * 256 + j as u32;
        let x = GENERATORS_EXP[offset as usize];
        tmp += x;
    }
    tmp
}

pub fn hash_combine(depth: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash = ExtendedPoint::identity();
    let mut acc = Fr::zero();
    let mut cur = Fr::one();

    let a = depth & 7;
    let b = depth >> 3;

    accumulate_scalar(&mut acc, &mut cur, a);
    cur = cur.double().double().double();
    accumulate_scalar(&mut acc, &mut cur, b);
    cur = cur.double().double().double();

    // Shift right by 1 bit and overwrite the 256th bit of left
    let mut left = *left;
    let mut right = *right;

    // move by 1 bit to fill the missing 256th bit of left
    let mut carry = 0;
    for i in (0..32).rev() {
        let c = right[i] & 1;
        right[i] = right[i] >> 1 | carry << 7;
        carry = c;
    }
    left[31] &= 0x7F;
    left[31] |= carry << 7; // move the first bit of right into 256th of left

    // we have 255*2/3 = 170 chunks
    let mut bit_offset = 0;
    let mut byte_offset = 0;
    let mut idx_generator = 0;
    for i in 0..170 {
        let mut v = if byte_offset < 31 {
            left[byte_offset] as u16 | (left[byte_offset + 1] as u16) << 8
        } else if byte_offset == 31 {
            left[31] as u16 | (right[0] as u16) << 8
        } else if byte_offset < 63 {
            right[byte_offset - 32] as u16 | (right[byte_offset - 31] as u16) << 8
        } else {
            right[byte_offset - 32] as u16
        };
        v = v >> bit_offset & 0x07; // keep 3 bits
        accumulate_scalar(&mut acc, &mut cur, v as u8);

        if (i+3) % PEDERSEN_HASH_CHUNKS_PER_GENERATOR as u32 == 0 {
            hash += accumulate_generator(&acc, idx_generator);
            idx_generator += 1;
            acc = Fr::zero();
            cur = Fr::one();
        }
        else {
            cur = cur.double().double().double(); // 2^4 * cur
        }
        bit_offset += 3;
        if bit_offset >= 8 {
            byte_offset += bit_offset / 8;
            bit_offset %= 8;
        }
    }
    hash += accumulate_generator(&acc, idx_generator);

    let hash = hash
        .to_affine()
        .get_u()
        .to_repr();
    hash
}

#[derive(Clone, Default)]
pub struct SaplingHasher {}

impl Hasher for SaplingHasher {
    fn uncommited_node() -> Node {
        [0u8; 32]
    }

    fn node_combine(&self, depth: u8, left: &Node, right: &Node) -> Node {
        hash_combine(depth, left, right)
    }
}


#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::pedersen_hash;
    use crate::sapling::hash::hash_combine;

    #[test]
    fn test_hash1() {
        let depth = 8;
        let sa = "767a9a7e989289efdfa69c4c8e985c31f3c2c0353f20a80f572854206f077f86";
        let sb = "944c46945a9e7a0a753850bd90f69d44ac884b60244a9f8eacf3a2aeddd08d6e";
        let a: [u8; 32] = hex::decode(sa).unwrap().try_into().unwrap();
        let b: [u8; 32] = hex::decode(sb).unwrap().try_into().unwrap();
        println!("A: {}", hex::encode(a));
        println!("B: {}", hex::encode(b));

        let hash = pedersen_hash(depth, &a, &b);
        let hash2 = hash_combine(depth, &a, &b);
        println!("Reference Hash: {}", hex::encode(hash));
        println!("This Hash:      {}", hex::encode(hash2));
        // need to expose repr for this check
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_random() {
        let mut rng = OsRng;
        for _ in 0..1000 {
            let depth = (rng.next_u32() % 50) as u8;
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut a);
            rng.fill_bytes(&mut b);
            println!("A: {}", hex::encode(a));
            println!("B: {}", hex::encode(b));

            let hash = pedersen_hash(depth, &a, &b);
            let hash2 = hash_combine(depth, &a, &b);
            println!("Reference Hash: {}", hex::encode(hash));
            println!("This Hash:      {}", hex::encode(hash2));
            // need to expose repr for this check
            assert_eq!(hash, hash2);
        }
    }
}
