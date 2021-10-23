use std::{fs, io};
use std::path::{PathBuf, Path};
use std::fs::DirEntry;
use rayon::prelude::*;
use std::sync::mpsc;
use std::str::FromStr;
use std::ffi::OsStr;
use pelite::{FileMap};
use pelite::pe64;
use pelite::pe64::{Pe, PeFile, PeObject};
use std::fmt::{Display};
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};
use pelite::Pod;
use iced_x86::{Register, Mnemonic};
use anyhow::*;

fn _main() {
    let info = DriverInfo::new(Path::new("C:/Users/Ryan/Desktop/win32kbase.sys")).expect("Could not make driver info");
    dbg!(info.contains_data_ptr());
}

fn main() {
    use itertools::Itertools;

    let drivers = get_files_with_ext(Path::new("F:/Cheating/Drivers"), "sys".to_owned());
    // let drivers = get_files_with_ext(Path::new("F:/"), "sys".to_owned()).chain(get_files_with_ext(Path::new("C:/"), "sys".to_owned()));
    let dlls = get_files_with_ext(Path::new("F:/Cheating/Drivers"), "dll".into()).collect::<Vec<_>>();
    let mut total_searched = AtomicUsize::new(0);
    let mut info = drivers.par_bridge()
        .map(|n| {
            total_searched.fetch_add(1, Ordering::SeqCst);
            n
        })
        .filter_map(|p| DriverInfo::new(&p)
            // .map_err(|e| println!("Could not parse driver {:?}: {:?}", p, e))
            .ok()
        )
        .filter(DriverInfo::creates_device)
        .filter(|i| i.contains_data_ptr().unwrap_or(false))
        // .filter(|info| {
        //     let name = info.path.file_stem().unwrap().to_str().unwrap();
        //     dlls.iter().map(|d| d.file_stem().unwrap().to_str().unwrap()).contains(&name)
        // })
        .map(|info: DriverInfo| {
            // dbg!(info);
            println!("{} ({} imports) ({} bytes)\n", info.name, info.imports.len(), info.size);
            info
        })
        .collect::<Vec<_>>();

    println!("--------");

    info.sort_by_key(|i| i.size);
    for i in &info {
        println!("{} ({} imports) ({} bytes)", i.name, i.imports.len(), i.size);
    }

    println!("[+] Searched {} drivers, found {} potentially vulnerable", total_searched.get_mut(), info.len());
    let file = fs::File::create("output.json").unwrap();
    serde_json::to_writer(file, &info).unwrap();
    println!("[+] Information written to output.json");
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DriverInfo {
    path: PathBuf,
    size: u64,
    name: String,
    imports: Vec<(String, String)>,
}

impl Display for DriverInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.name, self.imports.iter().map(|(_, func)| func).collect::<Vec<_>>())
    }
}

fn format_hex(n: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for (i, a) in n.iter().enumerate() {
        write!(s, "{:02X}", a).unwrap();
        if i != n.len()-1 {
            write!(s, " ").unwrap();
        }
    }
    s
}

impl DriverInfo {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let map = FileMap::open(path)?;
        let pe = pelite::pe64::PeFile::from_bytes(&map)?;

        let mut imports = Vec::new();
        for desc in pe.imports()? {
            let dll_name = desc.dll_name()?.to_string();

            let iat = desc.iat()?;
            let int = desc.int()?;

            for (va, import) in Iterator::zip(iat, int) {
                let import = import?;
                if let pe64::imports::Import::ByName { name, .. } = import {
                    imports.push((dll_name.clone(), name.to_string()));
                }
            }
        }

        let size = filesize::file_real_size(path)?;

        Ok(Self {
            path: path.into(),
            size,
            name: path.file_name().unwrap().to_str().unwrap().to_string(),
            imports,
        })
    }

    pub fn contains_data_ptr(&self) -> anyhow::Result<bool> {
        use iced_x86::Formatter;

        let map = FileMap::open(&self.path)?;
        let pe = pelite::pe64::PeView::from_bytes(&map)?;

        let get_section = |name| pe.section_headers().iter().find(|h| h.name() == Ok(name));
        let text = get_section(".text").ok_or_else(|| anyhow!("Could not find .text section"))?;
        let data = get_section(".data").ok_or_else(|| anyhow!("Could not get .data section"))?;

        // dbg!(pe.align());
        let text_bytes = pe.get_section_bytes(text)?;

        // dbg!(text.virtual_range());
        // for (mut i, b) in text_bytes.iter().enumerate() {
        //     i += text.virtual_range().start as usize;
        //     if i % 16 == 0 {
        //         println!();
        //         print!("{:#X}: ", i);
        //     }
        //     print!("{:02X} ", b);
        // }

        let mut d = iced_x86::Decoder::with_ip(64, text_bytes, text.virtual_range().start as _, iced_x86::DecoderOptions::NONE);

        let mut f = iced_x86::IntelFormatter::new();
        let mut fmt = String::new();

        let mut found = false;

        for i in d.iter() {
            fmt.clear();
            f.format(&i, &mut fmt);
            let offset = i.ip() as usize - text.virtual_range().start as usize;

            if i.memory_base() != Register::RIP {
                continue;
            }

            if i.mnemonic() != Mnemonic::Call {
                continue;
            }

            let read = i.memory_displacement64();
            if !data.virtual_range().contains(&(read as _)) {
                continue;
            }

            // println!("{:#X}: {: <36} {}", i.ip(), format_hex(&text_bytes[offset..offset + i.len() as usize]), fmt);
            found = true;
            break;
        }

        Ok(found)
    }

    fn imports(&self) -> Vec<&str> {
        self.imports.iter().map(|(_, func)| func.as_str()).collect::<Vec<_>>()
    }

    pub fn creates_device(&self) -> bool {
        self.imports().contains(&"IoCreateDevice")
    }

    pub fn maps_phys_memory(&self) -> bool {
        self.imports().contains(&"ZwMapViewOfSection")
    }
}

fn get_files_with_ext(dir: &Path, ext: String) -> impl Iterator<Item=PathBuf> {
    use itertools::Itertools;

    walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(|n| n
            // .map_err(|e| eprintln!("[-] Could not read file: {:?}", e))
            .ok())
        .map(|p| p.into_path())
        .filter(move |p| p.extension().map(OsStr::to_str) == Some(Some(&ext)))
        .unique_by(|p| p.file_name().map(OsStr::to_str).flatten().map(|s| s.to_string()))
}
