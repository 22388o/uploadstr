use poem::{get, post, handler, listener::TcpListener,
           web::Path, Route, Server, Result,
            Response, http::StatusCode, error::NotFoundError,
            EndpointExt, Body, Error};
use std::fs;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;


fn save_img(maybe_ext: Option<String>, data: Vec<u8>) -> String {
        let mut hasher = Sha256::new();
        let mut hash: [u8; 32] = [0; 32];

        hasher.input(&data);
        hasher.result(&mut hash);

        let hash = URL_SAFE_NO_PAD.encode(&hash);

        let filename = if let Some(ext) = maybe_ext {
            format!("{}.{}", hash, ext)
        } else {
            format!("{}", hash)
        };

        if let Ok(res) = fs::write(filename.clone(), data) {
            println!("Saved '{}'", filename);
        }
        else {
            println!("Could not save '{}'", filename);
        }

        filename
}

#[handler]
fn post_img(Path(ext): Path<String>, data: Vec<u8>) -> String {
    save_img(Some(ext), data)
}

#[handler]
fn post_img_without_ext(data: Vec<u8>) -> String {
    save_img(None, data)
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/upload", post(post_img_without_ext))
        .at("/upload/:ext", post(post_img))
        .catch_error(|err: NotFoundError| async move {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body("custom not found")
        });
    Server::new(TcpListener::bind("0.0.0.0:3000"))
      .run(app)
      .await
}
