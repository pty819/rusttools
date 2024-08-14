mod cryptfn;
use rpassword::read_password;
use std::env;
use std::fs;
use std::path::PathBuf;
extern crate mimalloc;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
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

fn match_normal_args(folder_path_str: &String, password: String) -> Action {
    let folder_path = PathBuf::from(folder_path_str);
    match (folder_path.is_dir(), fs::read(folder_path.join("salt.key"))) {
        (true, Ok(salt)) => Action::Decrypt {
            folder_path,
            password,
            salt,
        },
        (true, Err(_)) => Action::Encrypt {
            folder_path,
            password,
        },
        (false, _) => Action::Error("指定的路径不是一个文件夹。".to_string()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let action = match args.as_slice() {
        [_, folder_path_str, password_readed] => {
            let password = password_readed.to_string();
            match_normal_args(folder_path_str, password)
        }
        [_, folder_path_str] => {
            println!("请输入密码:");
            let password = read_password()?;
            match_normal_args(folder_path_str, password)
        }
        _ => Action::Error("请拖动一个文件夹到程序上或者直接指定文件夹路径作为参数。".to_string()),
    };

    match action {
        Action::Encrypt {
            folder_path,
            password,
        } => {
            let (less_safe_key, salt_arr) = cryptfn::generate_key_aead(password, None);
            println!("未发现salt.key,正在执行加密！");
            cryptfn::encrypt_loop(&folder_path, &less_safe_key, &salt_arr)
        }
        Action::Decrypt {
            folder_path,
            password,
            salt,
        } => {
            let mut salt_array = [0u8; cryptfn::SALT_LEN];
            salt_array.copy_from_slice(&salt[0..cryptfn::SALT_LEN]);
            println!("发现salt.key,正在执行解密！");
            let (less_safe_key, _) = cryptfn::generate_key_aead(password, Some(salt_array));
            cryptfn::decrypt_loop(&folder_path, &less_safe_key)
        }
        Action::Error(message) => {
            eprintln!("{}", message);
            Ok(())
        }
    }
}
