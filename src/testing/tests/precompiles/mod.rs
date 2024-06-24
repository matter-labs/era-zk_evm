use super::*;

mod keccak256;
// mod sha256;
mod ecrecover;
mod ecadd;
mod ecmul;
mod ecpairing;
mod modexp;

fn pretty_print_memory_dump(content: &Vec<[u8; 32]>, range: std::ops::Range<u32>) {
    println!("Memory dump:");
    println!("-----------------------------------------");
    for (cont, index) in content.into_iter().zip(range.into_iter()) {
        println!("{:04x}: 0x{}", index, hex::encode(cont));
    }
    println!("-----------------------------------------");
}
