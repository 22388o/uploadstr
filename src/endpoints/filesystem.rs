use std::fs::{create_dir_all,write};
use std::io::Result;
use std::path::Path;

pub fn save_file(filesDir: &str, filename: &String, data: &Vec<u8>) -> Result<()> {
        let folder = Path::new(filesDir);
        create_dir_all(folder)?;
        let path = folder.join(filename);
        write(&path, data)
}

pub fn get_files(filesDir: &str) -> Result<Vec<String>> {
        Path::new(filesDir)
        .read_dir()
        .map(|dir|
             dir.map(|res| res.map(|e| e.file_name().into_string()))
                .flatten()
                .flatten()
                .collect::<Vec<String>>()
        )
}
