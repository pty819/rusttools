use argon2::{self, Argon2};
use ring::aead::{self, LessSafeKey};
use ring::rand::{SecureRandom, SystemRandom};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub fn generate_key_aead(
    password: String,
    provided_salt: Option<[u8; SALT_LEN]>,
) -> (aead::LessSafeKey, [u8; SALT_LEN]) {
    let rng = SystemRandom::new();
    let salt = match provided_salt {
        Some(s) => s,
        None => {
            let mut new_salt = [0u8; SALT_LEN];
            rng.fill(&mut new_salt).expect("随机数生成失败");
            new_salt
        }
    };

    // 使用Argon2算法和盐值生成密钥
    let argon2 = Argon2::default();
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .unwrap();

    // 使用生成的密钥创建加密器
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).expect("密钥创建失败");
    (aead::LessSafeKey::new(unbound_key), salt)
}

pub fn encrypt_loop(
    folder_path: &PathBuf,
    less_safe_key: &LessSafeKey,
    salt: &[u8; SALT_LEN],
) -> Result<(), Box<dyn std::error::Error>> {
    let salt_path = folder_path.join("salt.key");
    fs::write(salt_path, salt)?;
    let rng = SystemRandom::new();
    WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .par_bridge()
        .for_each(|entry| {
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap() != "salt.key" {
                let encrypted_file = encrypt_single(less_safe_key, path, &rng);
                fs::write(path, encrypted_file).expect("写入失败");
                println!("文件 '{}' 已加密。", path.display());
            }
        });
    Ok(())
}

fn encrypt_single(less_safe_key: &LessSafeKey, path: &Path, rng: &SystemRandom) -> Vec<u8> {
    let mut file_content = fs::read(path).expect("读取文件失败");
    let mut nonce_arr = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_arr).expect("随机数生成失败");
    let nonce = aead::Nonce::assume_unique_for_key(nonce_arr); // 在实际应用中，应该使用唯一的nonce
    let aad = aead::Aad::empty(); // 附加的认证数据
    let mut final_data = nonce.as_ref().to_vec();
    let tag = less_safe_key
        .seal_in_place_separate_tag(nonce, aad, &mut file_content)
        .map_err(|_| "加密失败")
        .expect("加密失败"); // 加密文件内容

    let mut encrypted_file = file_content;
    encrypted_file.extend_from_slice(tag.as_ref());
    final_data.extend_from_slice(&encrypted_file);
    // encrypted_file
    final_data
}

pub fn decrypt_loop(
    folder_path: &PathBuf,
    less_safe_key: &LessSafeKey,
) -> Result<(), Box<dyn std::error::Error>> {
    WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .par_bridge()
        .for_each(|entry| {
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap() != "salt.key" {
                let decrypted_file = decrypt_single(less_safe_key, path);
                let _ = fs::write(path, decrypted_file);
                println!("文件 '{}' 已解密。", path.display());
            }
        });
    fs::remove_file(folder_path.join("salt.key"))?;
    Ok(())
}

fn decrypt_single(less_safe_key: &LessSafeKey, path: &Path) -> Vec<u8> {
    let mut file_content = fs::read(path).expect("读取文件失败");
    let (nonce_arr, encrypted_data) = file_content.split_at_mut(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_arr.try_into().expect("Nonce 转换失败");
    let nonce = aead::Nonce::assume_unique_for_key(nonce_arr);
    let aad = aead::Aad::empty();

    less_safe_key
        .open_in_place(nonce, aad, encrypted_data)
        .expect("解密失败")
        .to_vec()
}
