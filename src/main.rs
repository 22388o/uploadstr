use poem::{post, listener::TcpListener,
           Route, Server, Result,
           endpoint::StaticFilesEndpoint};
use poem::EndpointExt;
use poem::middleware::Cors;

mod nostr_auth;
mod upload;

use upload::upload_file;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/upload", post(upload_file))
        .nest(
            "/f",
            StaticFilesEndpoint::new("/Uploadstr/files")
        )
        .with(Cors::new().allow_credentials(true));

    Server::new(TcpListener::bind("0.0.0.0:3000"))
      .run(app)
      .await
}
