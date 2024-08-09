// 引入所需的模块
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, thread};
use tar::{Archive, Builder};
use zstd::stream::{Decoder, Encoder};

// 主函数，程序入口点
fn main() -> std::io::Result<()> {
    // 收集命令行参数
    let args: Vec<String> = env::args().collect();
    // 解析压缩级别，如果未提供或解析失败，则默认为5
    let compress_level: u32 = match args.get(2) {
        Some(level) => level.parse().unwrap_or_else(|_| {
            eprintln!("压缩等级错误，默认应该是5");
            5
        }),
        None => 5,
    };

    // 获取文件或文件夹路径
    let path_str = &args[1];
    let path = Path::new(path_str);
    // 记录操作开始时间
    let tar_start = Instant::now();
    // 根据路径类型执行压缩或解压缩操作
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
    // 计算操作耗时
    let tar_duration = tar_start.elapsed();
    // 输出操作结果和耗时
    println!(
        "{zst_result}位置的tar.zst任务执行完成！耗时：{:?}",
        tar_duration
    );
    // 暂停一秒钟，以便用户可以看到上面的信息
    thread::sleep(Duration::from_secs(1));
    Ok(())
}

// 创建tar.zst文件的函数
pub fn create_tar_zst(folder_path: &str, compresslevel: i32) -> io::Result<String> {
    // 创建文件路径对象
    let path = Path::new(folder_path);
    // 设置输出文件的路径
    let tar_zst_file_path = PathBuf::from(folder_path).with_extension("tar.zst");
    // 创建输出文件
    let tar_file = match File::create(&tar_zst_file_path) {
        Ok(file) => file,
        Err(e) => {
            // 如果创建文件失败，则尝试删除已创建的文件并返回错误
            let _ = fs::remove_file(&tar_zst_file_path);
            return Err(e);
        }
    };
    // 创建zstd编码器
    let mut encoder = Encoder::new(tar_file, compresslevel)?;
    // 启用多线程压缩
    encoder.multithread(num_cpus::get().try_into().unwrap())?;
    let _ = encoder.long_distance_matching(true);
    // 创建缓冲写入器
    let buffered_writer = BufWriter::new(encoder);
    // 创建tar构建器
    let mut tar_builder = Builder::new(buffered_writer);
    // 将文件夹内容添加到tar文件
    tar_builder.append_dir_all(path.file_name().unwrap(), path)?;
    // 完成tar文件的创建
    let encoder_finish = tar_builder.into_inner()?.into_inner()?;
    // 完成zstd压缩
    let mut zstd_compressor = encoder_finish.finish()?;
    // 刷新压缩器以确保所有数据都被写入
    zstd_compressor.flush()?;
    // 返回创建的tar.zst文件路径
    Ok(tar_zst_file_path.to_str().unwrap().to_owned())
}

// 解压tar.zst文件的函数
pub fn extract_tar_zst(file_path: &str) -> io::Result<String> {
    // 打开tar.zst文件
    let tar_zst_file = File::open(Path::new(file_path))?;
    // 创建zstd解码器
    let decoder = Decoder::new(tar_zst_file)?;
    // 创建tar归档对象
    let mut archive = Archive::new(decoder);
    // 解压tar归档到当前目录
    archive.unpack(".")?;
    // 返回解压的tar.zst文件路径
    Ok(file_path.to_owned())
}
