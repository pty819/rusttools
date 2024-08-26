// 引入所需的模块
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, thread};
use tar::{Archive, Builder};
use zstd::stream::{Decoder, Encoder};
extern crate mimalloc;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
// 主函数，程序入口点

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let compress_level: u32 = match args.get(2) {
        Some(level) => level.parse().unwrap_or_else(|_| {
            eprintln!("压缩等级错误，默认应该是5");
            5
        }),
        None => 5,
    };

    let path_str = &args[1];
    let path = Path::new(path_str);
    let tar_start = Instant::now();
    let zst_result = match path.metadata() {
        Ok(metadata) if metadata.is_file() && path_str.ends_with(".tar.zst") => {
            extract_tar_zst(path_str)?
        }
        Ok(metadata) if metadata.is_dir() => create_tar_zst(path_str, compress_level as i32)?,
        _ => {
            println!("需要一个文件夹或者tar.zst文件");
            path_str.to_string()
        }
    };
    let tar_duration = tar_start.elapsed();
    println!(
        "{zst_result}位置的tar.zst任务执行完成！耗时：{:?}",
        tar_duration
    );
    thread::sleep(Duration::from_secs(1));
    Ok(())
}

// 创建tar.zst文件的函数
pub fn create_tar_zst(folder_path: &str, compresslevel: i32) -> io::Result<String> {
    let path = Path::new(folder_path);
    let tar_zst_file_path = PathBuf::from(folder_path).with_extension("tar.zst");
    let tar_file = match File::create(&tar_zst_file_path) {
        Ok(file) => file,
        Err(e) => {
            let _ = fs::remove_file(&tar_zst_file_path);
            return Err(e);
        }
    };
    let mut encoder = Encoder::new(tar_file, compresslevel)?;
    encoder.multithread(num_cpus::get().try_into().unwrap())?;
    let _ = encoder.long_distance_matching(true);
    let buffered_writer = BufWriter::new(encoder);
    let mut tar_builder = Builder::new(buffered_writer);
    tar_builder.append_dir_all(path.file_name().unwrap(), path)?;
    let encoder_finish = tar_builder.into_inner()?.into_inner()?;
    let mut zstd_compressor = encoder_finish.finish()?;
    zstd_compressor.flush()?;
    Ok(tar_zst_file_path.to_str().unwrap().to_owned())
}

// 解压tar.zst文件的函数
pub fn extract_tar_zst(file_path: &str) -> io::Result<String> {
    let tar_zst_file = File::open(Path::new(file_path))?;
    let decoder = Decoder::new(tar_zst_file)?;
    let mut archive = Archive::new(decoder);
    archive.unpack(".")?;
    Ok(file_path.to_owned())
}
