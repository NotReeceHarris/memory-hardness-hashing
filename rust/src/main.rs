use sha3::{Digest, Sha3_256, Sha3_512};
use std::convert::TryInto;
use rand::Rng;
use std::time::Instant;

const BLOCK_SIZE_BYTES: usize = 32;

/// Hashes the input using SHA3-256.
fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Selects a random buffer from the array based on the first 8 bytes of the input data.
fn random(array: &[Vec<u8>], data: &[u8]) -> Vec<u8> {
    if array.is_empty() {
        panic!("Array cannot be empty");
    }

    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let random_value = u64::from_be_bytes(hash[..8].try_into().unwrap());
    let random_index = (random_value % array.len() as u64) as usize;

    array[random_index].clone()
}

/// Computes the Merkle root of an array of buffers.
fn merkle_root(buffers: &[Vec<u8>]) -> Vec<u8> {
    if buffers.is_empty() {
        panic!("Array of buffers cannot be empty");
    }

    let mut level: Vec<Vec<u8>> = buffers.iter().map(|buffer| hash(buffer)).collect();

    while level.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            let right = if i + 1 < level.len() { &level[i + 1] } else { left };
            let combined = [left.as_slice(), right.as_slice()].concat();
            next_level.push(hash(&combined));
        }
        level = next_level;
    }

    level[0].clone()
}

/// Computes a memory-hardened hash of the password using a memory matrix and time cost.
fn memory_harden_hash(password: &str, memory_cost_kib: usize, time_cost: usize, salt: &[u8]) -> String {
    let num_blocks = (memory_cost_kib * 1024) / BLOCK_SIZE_BYTES;

    if (memory_cost_kib * 1024) % BLOCK_SIZE_BYTES != 0 {
        panic!("Memory cost ({} KiB) must be a multiple of the block size ({} bytes).", memory_cost_kib, BLOCK_SIZE_BYTES);
    }

    let mut memory_matrix: Vec<Vec<u8>> = (0..num_blocks)
        .map(|i| {
            let buffer = [password.as_bytes(), salt, &i.to_string().into_bytes()].concat();
            hash(&buffer)
        })
        .collect();

    if memory_matrix.len() != num_blocks {
        panic!("Memory matrix size is not correct");
    }

    for _ in 0..time_cost {
        for i in 0..num_blocks {
            let curr_block = memory_matrix[i].clone();
            let prev_block = if i > 0 { memory_matrix[i - 1].clone() } else { memory_matrix[num_blocks - 1].clone() };
            let rand_block = random(&memory_matrix, &curr_block);

            let hash_input = [prev_block, rand_block].concat();
            let hash_output = hash(&hash_input);

            memory_matrix[i] = hash_output;
        }
    }

    let merkle_root_result = merkle_root(&memory_matrix);
    let final_hash = hash(&merkle_root_result);

    format!("$m={},$t={}${}${}", memory_cost_kib, time_cost, hex::encode(salt), hex::encode(final_hash))
}

/// Verifies a memory-hardened hash against a plaintext password.
fn memory_harden_verify(hashed: &str, plain: &str) -> bool {
    let parts: Vec<&str> = hashed.split('$').collect();

    if parts.len() != 5 {
        return false;
    }

    let memory_cost_kib = parts[1].split('=').nth(1).unwrap().parse::<usize>().unwrap();
    let time_cost = parts[2].split('=').nth(1).unwrap().parse::<usize>().unwrap();
    let salt = hex::decode(parts[3]).unwrap();
    let final_hash = hex::decode(parts[4]).unwrap();

    let computed_hash = memory_harden_hash(plain, memory_cost_kib, time_cost, &salt);
    let computed_final_hash = computed_hash.split('$').nth(4).unwrap();

    final_hash == hex::decode(computed_final_hash).unwrap()
}

fn main() {
    let password = "password";
    let memory_cost_kib = 2_usize.pow(16); // 64 MiB
    let time_cost = 3;

    let salt: Vec<u8> = rand::thread_rng().gen::<[u8; 64]>().to_vec();

    let start_time = Instant::now();
    let hash = memory_harden_hash(password, memory_cost_kib, time_cost, &salt);
    let hashing_time = start_time.elapsed();

    let start_time = Instant::now();
    let verify = memory_harden_verify(&hash, password);
    let verifying_time = start_time.elapsed();

    println!("Hashing Time: {:?}", hashing_time);
    println!("Verifying Time: {:?}", verifying_time);
    println!("Hash: {}", hash);
    println!("Verified: {}", if verify { "yes" } else { "no" });
}