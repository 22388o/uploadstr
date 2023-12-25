use std::fs;
use std::io::Result;

pub fn save_file(filename: &String, data: &Vec<u8>) -> Result<()> {
        let folder = std::path::Path::new("/Uploadstr/files/");
        fs::create_dir_all(folder)?;
        let path = folder.join(filename);
        fs::write(&path, data)
}
