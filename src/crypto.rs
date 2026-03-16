use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

// Result of encrypting a secret with envelope encryption
pub struct EncryptedPayload {
    pub encrypted_dek: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub content_nonce: Vec<u8>,
}

// Encrypt a secret using envelope encryption
// gen random DEK -> Encrypt content with DEK -> Encrypt DEK with KEK -> return all encrypted components - the raw DEK is dropped
pub fn encrypt_secret(kek: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPayload> {
    let dek = Aes256Gcm::generate_key(OsRng);

    let content_cipher = Aes256Gcm::new(&dek);
    let content_nonce_bytes: [u8; 12] = rand::random();
    let content_nonce = Nonce::from_slice(&content_nonce_bytes);
    let ciphertext = content_cipher
        .encrypt(content_nonce, plaintext)
        .map_err(|e| anyhow!("Content encryption failed: {}", e))?;

    let kek_cipher = Aes256Gcm::new(kek.into());
    let dek_nonce_bytes: [u8; 12] = rand::random();
    let dek_nonce = Nonce::from_slice(&dek_nonce_bytes);
    let encrypted_dek = kek_cipher
        .encrypt(dek_nonce, dek.as_slice())
        .map_err(|e| anyhow!("DEK encryption failed: {}", e))?;

    Ok(EncryptedPayload {
        encrypted_dek,
        dek_nonce: dek_nonce.to_vec(),
        ciphertext,
        content_nonce: content_nonce.to_vec(),
    })
}

// Decrypt a secret using envelope encryption (reverse of encrypt)
// Decrypt the DEK using the KEK -> Decrypt the content using the DEK
pub fn decrypt_secret(
    kek: &[u8; 32],
    encrypted_dek: &[u8],
    dek_nonce: &[u8],
    ciphertext: &[u8],
    content_nonce: &[u8],
) -> Result<Vec<u8>> {
    let kek_cipher = Aes256Gcm::new(kek.into());
    let dek_nonce = Nonce::from_slice(dek_nonce);
    let raw_dek = kek_cipher
        .decrypt(dek_nonce, encrypted_dek)
        .map_err(|e| anyhow!("DEK decryption failed: {}", e))?;

    let dek_array: [u8; 32] = raw_dek
        .try_into()
        .map_err(|e| anyhow!("Decrypted DEK is not 32 bytes"))?;
    let content_cipher = Aes256Gcm::new((&dek_array).into());
    let content_nonce = Nonce::from_slice(&content_nonce);
    let plaintext = content_cipher
        .decrypt(content_nonce, ciphertext)
        .map_err(|e| anyhow!("Content decryption failed: {}", e))?;

    Ok(plaintext)
}

// For user who wants to set password for some secret
// Hash a password using argon2id
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Password hashing failed: {}", e))?;

    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| anyhow!("Invalid password hash format: {}", e))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
