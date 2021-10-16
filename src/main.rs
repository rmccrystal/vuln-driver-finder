use std::{fs, io};
use std::path::{PathBuf, Path};
use std::fs::DirEntry;
use rayon::prelude::*;
use std::sync::mpsc;
use std::str::FromStr;
use std::ffi::OsStr;
use pelite::{FileMap};
use pelite::pe64;
use pelite::pe64::{Pe, PeFile};
use std::fmt::{Display, Formatter};
use itertools::Itertools;
use std::sync::atomic::{AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};

fn main() {
    // let drivers = get_drivers(PathBuf::from_str("F:/Cheating/Drivers").unwrap()).unwrap();
    let drivers = get_drivers(Path::new("F:/")).chain(get_drivers(Path::new("C:/")));
    let mut total_searched = AtomicUsize::new(0);
    let info = drivers.par_bridge()
        .map(|n| {
            total_searched.fetch_add(1, Ordering::SeqCst);
            n
        })
        .filter_map(|p| DriverInfo::new(&p)
            // .map_err(|e| println!("Could not parse driver {:?}: {:?}", p, e))
            .ok()
        )
        .filter(DriverInfo::vulnerable)
        .map(|info: DriverInfo| {
            // dbg!(info);
            println!("{} ({} imports)", info.name, info.imports.len());
            info
        })
        .collect::<Vec<_>>();

    println!("[+] Searched {} drivers, found {} potentially vulnerable", total_searched.get_mut(), info.len());
    let file = fs::File::create("output.json").unwrap();
    serde_json::to_writer(file, &info).unwrap();
    println!("[+] Information written to output.json");
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DriverInfo {
    path: PathBuf,
    name: String,
    imports: Vec<(String, String)>,
}

impl Display for DriverInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.name, self.imports.iter().map(|(_, func)| func).collect::<Vec<_>>())
    }
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

        Ok(Self {
            path: path.into(),
            name: path.file_name().unwrap().to_str().unwrap().to_string(),
            imports,
        })
    }

    pub fn vulnerable(&self) -> bool {
        self.imports.iter().map(|(_, func)| func).any(|func| func.to_lowercase() == "zwmapviewofsection")
    }
}

fn get_drivers(dir: &Path) -> impl Iterator<Item=PathBuf> {
    walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(|n| n
            // .map_err(|e| eprintln!("[-] Could not read file: {:?}", e))
            .ok())
        .map(|p| p.into_path())
        .filter(|p| p.extension().map(OsStr::to_str) == Some(Some("sys")))
        .unique_by(|p| p.file_name().map(OsStr::to_str).flatten().map(|s| s.to_string()))
}
