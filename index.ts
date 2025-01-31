import { createHash, randomBytes } from 'crypto';

// The size of a block in bytes (SHA3-256 output size)
const BLOCK_SIZE_BYTES = 32;

/**
 * Hashes the input (password or buffer) using SHA3-256.
 * @param password - The input to hash, which can be a Buffer.
 * @returns A Buffer containing the hashed output.
 */
function hash(data: Buffer): Buffer {
    const hex = createHash('sha3-256').update(data).digest('hex'); // Compute SHA3-256 hash in hex format
    const bytes = Buffer.from(hex, 'hex'); // Convert hex string to Buffer
    return bytes;
}

/**
 * Selects a random buffer from the array based on the first 4 bytes of the input data.
 * @param array - The array of Buffers to choose from.
 * @param data - The input data used to derive the random index.
 * @returns A randomly selected Buffer from the array.
 * @throws Error if the array is empty.
 */
function random(array: Buffer[], data: Buffer): Buffer {
    if (array.length === 0) {
        throw new Error('Array cannot be empty');
    }

    // Generate a 64-bit random value from the input data
    const hash = createHash('sha3-512').update(data).digest();

    // Convert the hash to a 64-bit unsigned integer using first 8 bytes of hash
    let randomValue: bigint = hash.readBigUInt64BE(0);
    
    let randomIndex: number;
    do {
        randomIndex = Number(randomValue % BigInt(array.length));
        randomValue = randomValue / BigInt(array.length);
    } while (randomIndex >= array.length);

    // Return the randomly selected buffer
    return array[randomIndex];
}

/**
 * Computes the Merkle root of an array of buffers.
 * @param buffers - The array of buffers to compute the Merkle root for.
 * @returns The Merkle root as a Buffer.
 * @throws Error if the array of buffers is empty.
 */
function merkleRoot(buffers: Buffer[]): Buffer {
    if (buffers.length === 0) {
        throw new Error('Array of buffers cannot be empty');
    }

    // Hash each buffer to create leaf nodes of the Merkle tree
    let level = buffers.map(buffer => hash(buffer));

    // Build the Merkle tree level by level until only one hash remains (the root)
    while (level.length > 1) {
        const nextLevel: Buffer[] = [];
        for (let i = 0; i < level.length; i += 2) {
            // Get the left and right children (use left child if no right child exists)
            const left = level[i];
            const right = (i + 1 < level.length) ? level[i + 1] : left;
            // Combine and hash the left and right children
            const combined = Buffer.concat([left, right]);
            nextLevel.push(hash(combined));
        }
        level = nextLevel;
    }

    // The final hash is the Merkle root
    return level[0];
}

/**
 * Computes a memory-hardened hash of the password using a memory matrix and time cost.
 * @param password - The password to hash.
 * @param memory_cost_kib - The memory cost in KiB (determines the size of the memory matrix).
 * @param time_cost - The time cost (number of iterations to perform).
 * @param salt - The salt to use for the hash (default is a random 64-byte buffer).
 * @returns The final hash as a hexadecimal string.
 * @throws Error if the memory cost is not a multiple of the block size.
 */
function memory_harden_hash(password: string, memory_cost_kib: number, time_cost: number, salt: Buffer = randomBytes(64)): string {

    // Calculate the number of blocks needed to fill the memory matrix
    const numBlocks = Math.floor((memory_cost_kib * 1024) / BLOCK_SIZE_BYTES);

    // Validate that the memory cost is a multiple of the block size
    if ((memory_cost_kib * 1024) % BLOCK_SIZE_BYTES !== 0) {
        throw new Error(`Memory cost (${memory_cost_kib} KiB) must be a multiple of the block size (${BLOCK_SIZE_BYTES} bytes).`);
    }

    // Fill the memory matrix with blocks derived from the password, salt, and index
    const memory_matrix = Array.from({ length: numBlocks }, (_, i) => {
        const buffer = Buffer.concat([
            Buffer.from(password),
            salt,
            Buffer.from(i.toString())
        ]);
        return hash(buffer);
    });

    // Validate that the memory matrix has the correct number of blocks
    if (memory_matrix.length !== numBlocks) {
        throw new Error('Memory matrix size is not correct');
    }

    // Perform memory-hard computation for the specified number of iterations (time cost)
    for (let t = 0; t < time_cost; t++) {
        for (let i = 0; i < numBlocks; i++) {

            const curr_block = memory_matrix[i];

            // Get the previous block (or the last block if this is the first block)
            const prev_block = i > 0 ? memory_matrix[i - 1] : memory_matrix[numBlocks - 1];
            // Select a random block from the memory matrix
            const rand_block = random(memory_matrix, curr_block);

            // Combine the previous block and the random block, then hash the result
            const hash_input = Buffer.concat([prev_block, rand_block]);
            const hash_output = hash(hash_input);

            // Update the current block in the memory matrix
            memory_matrix[i] = hash_output;
        }
    }

    // Compute the Merkle root of the memory matrix as the final hash
    let merkleRoot_result = merkleRoot(memory_matrix);
    // Hash the Merkle root to produce the final output
    let final_hash = hash(merkleRoot_result);

    // Return the final hash as a hexadecimal string
    return `$m=${memory_cost_kib},$t=${time_cost}$${salt.toString('hex')}$${final_hash.toString('hex')}`;
}

function memory_harden_verify(hashed: string, plain: string): boolean {
    const parts = hashed.split('$');

    if (parts.length !== 5) {
        return false;
    }

    const memory_cost_kib = parseInt(parts[1].split('=')[1]);
    const time_cost = parseInt(parts[2].split('=')[1]);
    const salt = Buffer.from(parts[3], 'hex');
    const final_hash = Buffer.from(parts[4], 'hex');

    const computed_hash = memory_harden_hash(plain, memory_cost_kib, time_cost, salt);
    return final_hash.equals(Buffer.from(computed_hash.split('$')[4], 'hex'));

}

// Example usage: Compute a memory-hardened hash with 64 MiB memory cost and 3 iterations
(async () => {

    const password = 'password';
    const memory_cost_kib = 2 ** 16; // 64 MiB
    const time_cost = 3;

    console.time('Hashing Time');
    const hash = memory_harden_hash(password, memory_cost_kib, time_cost);
    console.timeEnd('Hashing Time');

    console.time('Verifing Time');
    const verify = memory_harden_verify(hash, password);
    console.timeEnd('Verifing Time');

    console.log('hash', hash);
    console.log('verified', verify ? 'yes' : 'no')

})();
