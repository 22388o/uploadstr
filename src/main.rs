use poem::{get, post, listener::TcpListener,
           Route, Server,
           endpoint::StaticFilesEndpoint};
use poem::EndpointExt;
use poem::middleware::Cors;

mod nostr_auth;
mod endpoints;
mod config;

use endpoints::upload_file;
use endpoints::list_files;
use config::get_config_value;

#[tokio::main]
async fn main() -> () {
    let filesDir = get_config_value("filesDir").unwrap();
    let bind = get_config_value("bind").unwrap();

    let app = Route::new()
        .at("/upload", post(upload_file))
        .at("/list", get(list_files))
        .nest(
            "/f",
            StaticFilesEndpoint::new(filesDir)
        )
        .with(Cors::new().allow_credentials(true));

    Server::new(TcpListener::bind(bind))
      .run(app)
      .await;
}
