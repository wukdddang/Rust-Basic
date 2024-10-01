use rand::Rng;
use sha2::{Sha256, Digest};
use hex;

struct Wallet {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl Wallet {
    fn new() -> Self {
        let private_key = rand::thread_rng().gen::<[u8; 32]>();
        let public_key = Self::generate_public_key(&private_key);
        Wallet { private_key, public_key }
    }

    fn generate_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(private_key);
        hasher.finalize().into()
    }

    fn get_address(&self) -> String {
        hex::encode(&self.public_key[..])
    }

    fn sign_transaction(&self, transaction: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(transaction.as_bytes());
        hasher.update(&self.private_key);
        hex::encode(hasher.finalize())
    }

    fn verify_signature(&self, transaction: &str, signature: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(transaction.as_bytes());
        hasher.update(&self.private_key);
        let expected_signature = hex::encode(hasher.finalize());
        expected_signature == signature
    }
}

fn main() {
    let wallet = Wallet::new();
    println!("Wallet address: {}", wallet.get_address());

    let transaction = "Send 1 BTC to Alice";
    let signature = wallet.sign_transaction(transaction);
    println!("Transaction: {}", transaction);
    println!("Signature: {}", signature);

    let is_valid = wallet.verify_signature(transaction, &signature);

    if is_valid {
        println!("Signature is valid");
    } else {
        println!("Signature is invalid");
    }
}