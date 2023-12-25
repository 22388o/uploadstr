use poem::{handler, Result, http::StatusCode, Error};

mod save;
use save::save_file;

use crate::nostr_auth::parse::NostrAuth;
use crate::nostr_auth::check::check_file_auth;


fn print_result(f: impl FnOnce() -> Result<String>) -> Result<String> {
    let result = f();
    println!("{:#?}", result);
    return result;
}


#[handler]
pub fn upload_file(auth: NostrAuth, data: Vec<u8>) -> Result<String> {
    let baseUrl = "http://0.0.0.0:3000";

    print_result(|| {
        check_file_auth(&auth.get_event(), &data)
            .and_then(|filename|
                save_file(&filename, &data)
                    .map(|_| format!("{}/f/{}", baseUrl, filename))
                    .map_err(|_| Error::from_string(
                        "Could not save file to server.",
                        StatusCode::INTERNAL_SERVER_ERROR
                    ))
            )
    })
}
