use poem::{Result, http::StatusCode, Error};
use nostr::event::kind::Kind;
use nostr::event::tag::Tag;
use nostr::types::time::Timestamp;
use nostr::event::tag::HttpMethod;
use nostr::event::Event;
use nostr::UncheckedUrl;
use std::ops::Add;
use nostr::event::tag::TagKind;

use crypto::sha2::Sha256;
use crypto::digest::Digest;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn check_file_auth(event: &Event, data: &Vec<u8>) -> Result<String> {
        check_auth(event)?;

        let mut payloads =
            event
            .tags
            .iter()
            .filter_map(
                |tag| match tag {
                    Tag::Payload(hash) => Some(hash),
                    _ => None
                }
            );


        let payload = payloads.nth(0);


        if payload.is_some() {
            if let Some(_) = payloads.nth(0) {
                return Err(
                    Error::from_string(
                        "There are two payload hashes.",
                        StatusCode::UNAUTHORIZED
                    )
                );
            }
        }

        if !payload.is_some() {
            return Err(
                Error::from_string(
                    "The payload hash is missing.",
                    StatusCode::UNAUTHORIZED
                )
            );
        }

        let actual_hash = payload.unwrap();

        let mut hasher = Sha256::new();
        let mut sha256_hash: [u8; 32] = [0; 32];

        hasher.input(&data);
        hasher.result(&mut sha256_hash);

        if actual_hash.as_ref() != sha256_hash {
            return Err(
                Error::from_string(
                    "The given SHA256 hash does not match with the given binary data",
                    StatusCode::UNAUTHORIZED
                )
            );
        }

        let b64 = URL_SAFE_NO_PAD.encode(&sha256_hash);


        let ext_str = String::from("ext");

        let mut exts =
            event
            .tags
            .iter()
            .filter_map(
                |tag| match tag {
                    Tag::Generic(
                        TagKind::Custom(
                            ext_str
                        ),
                        ext_arr
                    ) => Some(ext_arr),
                    _ => None
                }
            );


        let ext_vec = exts.nth(0);


        if ext_vec.is_some() {
            if let Some(_) = exts.nth(0) {
                return Err(
                    Error::from_string(
                        "There are multiple ext tags.",
                        StatusCode::BAD_REQUEST
                    )
                );
            }
        }

        let filename =
            if let Some(exts) = ext_vec {
                if exts.len() != 1 {
                    return Err(
                        Error::from_string(
                            "There are multiple ext specified.",
                            StatusCode::BAD_REQUEST
                        )
                    );
                }

                let ext = &exts[0];

                format!("{}.{}", b64, ext)
            } else {
                format!("{}", b64)
            };

        Ok(filename)

}

pub fn check_auth(event: &Event) -> Result<()> {
    event
        .verify()
        .map_err(|_| Error::from_string(
            "EventId/Signature are not valid...",
            StatusCode::UNAUTHORIZED
        ))?;

    if event.kind != Kind::HttpAuth {
        return Err(
            Error::from_string(
                "Incorrect kind. Must be 27235.",
                StatusCode::UNAUTHORIZED
            )
        );
    }

    if event.created_at.add(60 as i64) < Timestamp::now() {
        return Err(
            Error::from_string(
                "Event was not created within the past 60 seconds.",
                StatusCode::UNAUTHORIZED
            )
        );
    }

    if event.created_at > Timestamp::now() {
        return Err(
            Error::from_string(
                "This event is from the future...",
                StatusCode::UNAUTHORIZED
            )
        );
    }

    let mut urls = event
        .tags
        .iter()
        .filter_map(
            |tag| match tag {
                Tag::AbsoluteURL(url) => Some(url),
                _ => None
            }
        );

    if Some(UncheckedUrl::from("http://0.0.0.0:3000/upload")) != urls.nth(0).cloned()
        || urls.nth(0).is_some() // Checks for multiple u tags...
    {
        return Err(
            Error::from_string(
                "The u tag is not the correct url or there are multiple u tags.",
                StatusCode::UNAUTHORIZED
            )
        );
    }

    let mut methods = event
        .tags
        .iter()
        .filter_map(
            |tag| match tag {
                Tag::Method(method) => Some(method),
                _ => None
            }
        );


    if Some(HttpMethod::POST) != methods.nth(0).cloned()
        || methods.nth(0).is_some() // Checks for multiple method tags...
    {
        return Err(
            Error::from_string(
                "The method tag is not POST or there are multiple method tags",
                StatusCode::UNAUTHORIZED
            )
        );
    }

    return Ok(());
}