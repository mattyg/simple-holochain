// Helper utility

pub fn hash<H: Hash>(val: H) -> &[u8] {
    let mut hash_bytes = &[];
    val.hash(&mut hash_bytes);
    hash_bytes
}
