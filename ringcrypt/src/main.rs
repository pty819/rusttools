mod cryptfn;
use rpassword::read_password;
use std::env;
use std::fs;
use std::path::PathBuf;

// 定义一个枚举来表示不同的程序状态
enum Action {
    Encrypt {
        folder_path: PathBuf,
        password: String,
    },
    Decrypt {
        folder_path: PathBuf,
        password: String,
        salt: Vec<u8>,
    },
    Error(String),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let action = match args.as_slice() {
        [_, folder_path_str, password] => {
            let folder_path = PathBuf::from(folder_path_str);
            match (folder_path.is_dir(), fs::read(folder_path.join("salt.key"))) {
                (true, Ok(salt)) => Action::Decrypt {
                    folder_path,
                    password: password.to_string(),
                    salt,
                },
                (true, Err(_)) => Action::Encrypt {
                    folder_path,
                    password: password.to_string(),
                },
                (false, _) => Action::Error("指定的路径不是一个文件夹。".to_string()),
            }
        }
        [_, folder_path_str] => {
            let folder_path = PathBuf::from(folder_path_str);
            println!("请输入密码:");
            let password_input = read_password()?;
            match (folder_path.is_dir(), fs::read(folder_path.join("salt.key"))) {
                (true, Ok(salt)) => Action::Decrypt {
                    folder_path,
                    password: password_input,
                    salt,
                },
                (true, Err(_)) => Action::Encrypt {
                    folder_path,
                    password: password_input,
                },
                (false, _) => Action::Error("指定的路径不是一个文件夹。".to_string()),
            }
        }
        _ => Action::Error("请拖动一个文件夹到程序上或者直接指定文件夹路径作为参数。".to_string()),
    };

    match action {
        Action::Encrypt {
            folder_path,
            password,
        } => {
            let (less_safe_key, salt_arr) = cryptfn::generate_key_aead(password, None);
            cryptfn::encrypt_loop(&folder_path, &less_safe_key, &salt_arr)
        }
        Action::Decrypt {
            folder_path,
            password,
            salt,
        } => {
            let mut salt_array = [0u8; 32];
            salt_array.copy_from_slice(&salt[0..32]);
            let (less_safe_key, _) = cryptfn::generate_key_aead(password, Some(salt_array));
            cryptfn::decrypt_loop(&folder_path, &less_safe_key)
        }
        Action::Error(message) => {
            eprintln!("{}", message);
            Ok(())
        }
    }
}
