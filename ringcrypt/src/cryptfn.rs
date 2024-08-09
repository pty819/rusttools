use rayon::prelude::*;
use ring::aead;
use ring::aead::LessSafeKey;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::ErrorKind;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::{fs, io};
use walkdir::WalkDir;

pub fn generate_key_aead(
    password: String,
    provided_salt: Option<[u8; 32]>,
) -> (aead::LessSafeKey, [u8; 32]) {
    let rng = SystemRandom::new();
    let salt = match provided_salt {
        Some(s) => s,
        None => {
            let mut new_salt = [0u8; 32];
            rng.fill(&mut new_salt).expect("随机数生成失败");
            new_salt
        }
    };

    // 使用PBKDF2算法和盐值生成密钥
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );

    // 使用生成的密钥创建加密器
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).expect("密钥创建失败");
    (aead::LessSafeKey::new(key), salt)
}

pub fn encrypt_loop(
    folder_path: &PathBuf,
    aead: &LessSafeKey,
    salt: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let rng = SystemRandom::new();
    WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .par_bridge()
        .for_each(|entry| {
            let path = entry.path();
            if path.is_file() {
                let encrypted_file = encrypt_single(aead, path, &rng);
                fs::write(path, encrypted_file).expect("写入失败");
                println!("文件 '{}' 已加密。", path.display());
            }
        });

    // 保存盐值到文本文件
    let salt_path = folder_path.join("salt.key");
    fs::write(salt_path, salt)?;
    Ok(())
}

fn encrypt_single(less_safe_key: &LessSafeKey, path: &Path, rng: &SystemRandom) -> Vec<u8> {
    let mut file_content = fs::read(path).expect("读取文件失败");
    let mut nonce_arr = [0u8;12];
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
                fs::write(path, decrypted_file);
                println!("文件 '{}' 已解密。", path.display());
            }
        });
    fs::remove_file(folder_path.join("salt.key"))?;
    Ok(())
}

fn decrypt_single(less_safe_key: &LessSafeKey, path: &Path) -> Vec<u8> {
    let mut file_content = fs::read(path)?;
    let (nonce_arr, encrypted_data) = file_content.split_at(12);
    let nonce_arr: [u8; 12] = nonce_arr.try_into().expect("Nonce conversion failed");
    let nonce = aead::Nonce::assume_unique_for_key(nonce_arr);
    let aad = aead::Aad::empty();

    let ret = less_safe_key
        .open_in_place(nonce, aad, encrypted_data)
        .map(|decrypted_data| decrypted_data.to_vec())
        .map_err(|e| Box::new(io::Error::new(ErrorKind::InvalidData, "解密失败")) as Box<dyn std::error::Error>);

    ret.as_ref()
    
}