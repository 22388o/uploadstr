use poem::{handler, Result, http::StatusCode, Error};

mod filesystem;
use filesystem::save_file;
use filesystem::get_files;

use crate::nostr_auth::parse::NostrAuth;
use crate::nostr_auth::check::check_file_auth;
use crate::nostr_auth::check::check_auth;
use crate::config::get_config_value;

use serde_json::to_string;
use nostr::HttpMethod;


fn print_result(f: impl FnOnce() -> Result<String>) -> Result<String> {
    let result = f();
    println!("{:#?}", result);
    return result;
}


#[handler]
pub fn upload_file(auth: NostrAuth, data: Vec<u8>) -> Result<String> {
    print_result(|| {
        check_file_auth(&auth.get_event(), &data)
            .and_then(|filename|
                get_config_value("baseUrl")
                .and_then(|baseUrl|
                    get_config_value("filesDir")
                    .and_then(|filesDir|
                        save_file(&filesDir, &filename, &data)
                            .map(|_| format!("{}/f/{}", baseUrl, filename))
                            .map_err(|_| Error::from_string(
                                "Could not save file to server.",
                                StatusCode::INTERNAL_SERVER_ERROR
                            ))
                    )
                )
            )
    })
}

#[handler]
pub fn list_files(auth: NostrAuth) -> Result<String> {
    print_result(|| {
        check_auth(&auth.get_event(), HttpMethod::GET, "/list")?;

        get_config_value("baseUrl")
        .and_then(|baseUrl|
            get_config_value("filesDir")
            .and_then(|filesDir|
                get_files(&filesDir)
                .map_err(|_| Error::from_string(
                    "Failed to get list of files",
                    StatusCode::INTERNAL_SERVER_ERROR
                ))
                .map(|list|
                    list.into_iter().map(|filename| format!("{}/f/{}", baseUrl, filename)).collect::<Vec<String>>()
                )
                .and_then(|v|
                    to_string(&v)
                    .map_err(|_| Error::from_string(
                        "Failed to convert reply to JSON",
                        StatusCode::INTERNAL_SERVER_ERROR
                    ))
                )
            )
        )
    })
}
