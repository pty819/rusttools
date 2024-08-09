mod cryptfn;
use rpassword::read_password;
use std::path::PathBuf;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 检查是否有命令行参数（文件夹路径）
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("请拖动一个文件夹到程序上或者直接指定文件夹路径作为参数。");
        return Ok(());
    }
    let folder_path = PathBuf::from(&args[1]);
    if !folder_path.is_dir() {
        eprintln!("指定的路径不是一个文件夹。");
        return Ok(());
    }

    let salt_path = folder_path.join("salt.key");
    let salt = if salt_path.exists() {
        println!("检测到salt文件！执行解密任务！");
        // 如果存在，读取 salt.key 的内容
        Some(fs::read(salt_path)?)
    } else {
        println!("未检测到salt文件！执行加密任务！");
        // 如果不存在，传入 None
        None
    };
    // 获取用户输入的密码
    println!("请输入密码:");
    let password = read_password()?;

    // 根据 salt 的存在与否调用 generate_key_aead 函数
    let (less_safe_key, salt_arr) = match salt.clone() {
        Some(s) => {
            // 确保读取的 salt 是正确的长度
            let mut salt_array = [0u8; 32];
            salt_array.copy_from_slice(&s[0..32]);
            cryptfn::generate_key_aead(password, Some(salt_array))
        }
        None => cryptfn::generate_key_aead(password, None),
    };

    // 加密/解密文件夹中的所有文件
    match salt {
        Some(_) => cryptfn::decrypt_loop(&folder_path, &less_safe_key),
        None => cryptfn::encrypt_loop(&folder_path, &less_safe_key, &salt_arr),
    }

}
