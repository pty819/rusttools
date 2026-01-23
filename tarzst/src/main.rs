use crossbeam_channel::{bounded, Receiver, Sender};
use mimalloc::MiMalloc;
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Instant;
use tar::{Archive, Builder, Header};
use typed_path::{UnixPathBuf, Path as TypedPath};
use jwalk::{WalkDir, Parallelism}; // 核心替换：并行遍历库
use zstd::stream::{Decoder, Encoder};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// --- 极致调优参数 ---
const LARGE_FILE_THRESHOLD: u64 = 50 * 1024 * 1024; // 50MB
const IO_BUFFER_SIZE: usize = 4 * 1024 * 1024;      // 4MB (对齐 SSD Page)
const POOL_ITEM_SIZE: usize = 1024 * 1024;          // 1MB

// --- 内存池 (无需变动，已是最优) ---
#[derive(Clone)]
struct BufferPool {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl BufferPool {
    fn new(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity);
        (0..capacity).for_each(|_| { let _ = tx.send(Vec::with_capacity(POOL_ITEM_SIZE)); });
        Self { tx, rx }
    }
    fn checkout(&self) -> Vec<u8> {
        self.rx.try_recv().unwrap_or_else(|_| Vec::with_capacity(POOL_ITEM_SIZE))
    }
    fn recycle(&self, mut buf: Vec<u8>) {
        buf.clear();
        let _ = self.tx.try_send(buf);
    }
}

// --- 工件定义 ---
enum Artifact {
    Memory { path: PathBuf, meta: Metadata, data: Vec<u8> },
    LargeFile { path: PathBuf, meta: Metadata, len: u64 },
    Symlink { path: PathBuf, target: PathBuf, meta: Metadata },
    Dir { path: PathBuf, meta: Metadata },
    Fail { err: String },
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let Some(input) = args.get(1) else { return Ok(()); };
    let path = Path::new(input);
    
    let start = Instant::now();

    if path.is_dir() {
        let level = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        println!("🚀 [极速模式] 并行打包: {}", input);
        pack_parallel_jwalk(path, level)?;
    } else if input.ends_with(".tar.zst") {
        println!("📦 [极速模式] 解包: {}", input);
        unpack_stream(path)?;
    }
    
    println!("⏱️ 总耗时: {:?}", start.elapsed());
    Ok(())
}

// ==========================================
// 🚀 jwalk 并行扫描 + 流水线打包
// ==========================================

fn pack_parallel_jwalk(root: &Path, level: i32) -> io::Result<()> {
    let out_path = root.with_extension("tar.zst");
    let num_cores = num_cpus::get();
    
    // 线程策略调优：
    // Zstd 是 CPU 密集型，IO 线程是等待型。
    // 如果全部分配满，操作系统调度会有压力。
    // 策略：Zstd 占用绝大多数核，留 2 个核给 IO 调度和扫描。
    let zstd_threads = if num_cores > 4 { num_cores - 2 } else { num_cores };
    let io_threads = std::cmp::min(num_cores, 8); // IO 并发度 8 足够跑满 NVMe

    let (path_tx, path_rx) = bounded::<PathBuf>(1024); // 加大队列缓冲扫描峰值
    let (art_tx, art_rx) = bounded::<Artifact>(256);
    let pool = BufferPool::new(io_threads * 2);

    thread::scope(|s| {
        // [Stage 1] 扫描器：使用 jwalk 并行扫描
        s.spawn(|| {
            // jwalk 会自动利用多核扫描目录，速度远超 walkdir
            WalkDir::new(root)
                .skip_hidden(false)
                .parallelism(Parallelism::RayonNewPool(2)) // 限制扫描线程数，避免抢占 Zstd 资源
                .into_iter()
                .filter_map(|e| e.ok())
                .for_each(|entry| {
                    // jwalk 返回的 entry 已经包含了 path
                    let _ = path_tx.send(entry.path());
                });
        });

        // [Stage 2] IO Workers
        for _ in 0..io_threads {
            let rx = path_rx.clone();
            let tx = art_tx.clone();
            let pool = pool.clone();
            s.spawn(move || {
                for path in rx {
                    let art = process_entry(path, &pool);
                    if tx.send(art).is_err() { break; }
                }
            });
        }
        drop(art_tx);

        // [Stage 3] Archiver
        write_tar_zst(&out_path, root, art_rx, &pool, level, zstd_threads as u32)
    })
}

#[inline]
fn process_entry(path: PathBuf, pool: &BufferPool) -> Artifact {
    // 依然需要 symlink_metadata，因为我们需要精确的元数据（权限/时间）
    // 即使 jwalk 可能提供了部分信息，为了稳健性，这里做一次 syscall 是值得的
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Artifact::Fail { err: format!("Stat fail: {:?}", path) };
    };

    let file_type = meta.file_type();

    if file_type.is_dir() { return Artifact::Dir { path, meta }; }
    
    if file_type.is_symlink() {
        return match fs::read_link(&path) {
            Ok(target) => Artifact::Symlink { path, target, meta },
            Err(e) => Artifact::Fail { err: format!("Link error: {}", e) },
        };
    }

    let len = meta.len();
    if len > LARGE_FILE_THRESHOLD {
        return Artifact::LargeFile { path, meta, len };
    }

    let mut buf = pool.checkout();
    if (len as usize) > buf.capacity() {
        buf.reserve(len as usize - buf.len());
    }

    // 极速路径：小文件读取
    let Ok(mut f) = File::open(&path) else {
        pool.recycle(buf);
        return Artifact::Fail { err: format!("Open error: {:?}", path) };
    };

    if let Err(e) = f.read_to_end(&mut buf) {
        pool.recycle(buf);
        return Artifact::Fail { err: format!("Read error: {}", e) };
    }

    Artifact::Memory { path, meta, data: buf }
}

fn write_tar_zst(
    dest: &Path, 
    root: &Path, 
    rx: Receiver<Artifact>, 
    pool: &BufferPool, 
    level: i32,
    zstd_threads: u32
) -> io::Result<()> {
    let file = File::create(dest)?;
    let file_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, file);
    
    let mut encoder = Encoder::new(file_writer, level)?;
    // 关键优化：不占满所有核，留给 IO
    encoder.multithread(zstd_threads)?; 
    let _ = encoder.long_distance_matching(true);

    let encoder_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, encoder);
    let mut tar = Builder::new(encoder_writer);

    // 路径标准化闭包 (Pre-allocated buffer could be optimized here, but typed-path is fast enough)
    let normalize_path = |p: &Path| -> UnixPathBuf {
        let rel = p.strip_prefix(root.parent().unwrap_or(Path::new("/"))).unwrap_or(p);
        let mut unix_path = UnixPathBuf::new();
        for component in rel.components() {
            match component {
                Component::Normal(c) => unix_path.push(c.to_string_lossy().as_bytes()),
                Component::ParentDir => unix_path.push(".."),
                Component::CurDir => unix_path.push("."),
                _ => {} 
            }
        }
        unix_path
    };

    for art in rx {
        match art {
            Artifact::Memory { path, meta, data } => {
                let mut header = Header::new_gnu();
                header.set_metadata(&meta);
                header.set_size(data.len() as u64);
                header.set_cksum();
                
                let _ = tar.append_data(&mut header, normalize_path(&path), &data[..]);
                pool.recycle(data);
            }
            Artifact::LargeFile { path, meta, len } => {
                let mut header = Header::new_gnu();
                header.set_metadata(&meta);
                header.set_size(len);
                header.set_cksum();
                if let Ok(mut f) = File::open(&path) {
                    let mut reader = f.take(len); // TOCTOU Protection
                    let _ = tar.append_data(&mut header, normalize_path(&path), &mut reader);
                }
            }
            Artifact::Symlink { path, target, meta } => {
                let mut header = Header::new_gnu();
                header.set_metadata(&meta);
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                
                let target_unix = {
                    let mut t = UnixPathBuf::new();
                    for c in target.components() {
                        if let Component::Normal(s) = c { t.push(s.to_string_lossy().as_bytes()); }
                    }
                    t
                };
                let _ = header.set_link_name(target_unix);
                header.set_cksum();
                let _ = tar.append_data(&mut header, normalize_path(&path), &mut io::empty());
            }
            Artifact::Dir { path, meta } => {
                let mut header = Header::new_gnu();
                header.set_metadata(&meta);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_cksum();
                let _ = tar.append_data(&mut header, normalize_path(&path), &mut io::empty());
            }
            Artifact::Fail { err } => eprintln!("⚠️ {}", err),
        }
    }

    tar.into_inner()?.into_inner()?.finish()?.flush()?;
    Ok(())
}

fn unpack_stream(tar_zst_path: &Path) -> io::Result<()> {
    let file = File::open(tar_zst_path)?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
    let decoder = Decoder::new(reader)?;
    let mut archive = Archive::new(decoder);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.unpack(".")
}
