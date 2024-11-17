use crate::error::{ChorusError, Error};
use crate::filestore::HashOutput;
use crate::globals::GLOBALS;
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ALLOW, CONTENT_LENGTH,
    CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE,
};
use http::{Method, StatusCode};
//ACCEPT, AUTHORIZATION, DATE, ETAG, ORIGIN
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use serde::{Deserialize, Serialize};

mod auth;
use auth::{verify_auth, AuthVerb};

pub async fn handle(request: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    match route(request).await {
        Ok(response) => Ok(response),
        Err(e) => match e.inner {
            ChorusError::SignalNotBlossom => Err(e),
            _ => error_response(e),
        },
    }
}

pub async fn route(request: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    let p = request.uri().path();
    if p.starts_with("/")
        && p.len() >= 1 + 64
        && p.chars().skip(1).take(64).all(|c| c.is_ascii_hexdigit())
    {
        handle_hash(request).await
    } else if p == "/upload" {
        handle_upload(request).await
    } else if p.starts_with("/list/")
        && p.len() >= 6 + 64
        && p.chars().skip(6).take(64).all(|c| c.is_ascii_hexdigit())
    {
        handle_list(request).await
    } else if p == "/mirror" {
        handle_mirror(request).await
    } else {
        Err(ChorusError::SignalNotBlossom.into())
    }
}

fn error_response(e: Error) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    use std::io::ErrorKind;

    let mut response = Response::builder().header(ACCESS_CONTROL_ALLOW_ORIGIN, "*");

    let (status, reason) = match e.inner {
        ChorusError::BlossomAuthFailure(m) => {
            response = response.header(WWW_AUTHENTICATE, "Nostr");
            (StatusCode::UNAUTHORIZED, m)
        }
        ChorusError::FromHex(_) => (StatusCode::BAD_REQUEST, format!("{e}")),
        ChorusError::Io(ref ioerror) => match ioerror.kind() {
            ErrorKind::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_owned()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
        },
        _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    };

    Ok(response
        .header("X-Reason", reason)
        .status(status)
        .body(Empty::new().map_err(|e| e.into()).boxed())?)
}

fn options_response(
    request: Request<Incoming>,
    methods: &str,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if request
        .headers()
        .contains_key(ACCESS_CONTROL_REQUEST_HEADERS)
        || request
            .headers()
            .contains_key(ACCESS_CONTROL_REQUEST_METHOD)
        || request.headers().contains_key(ORIGIN)
    {
        // CORS OPTIONS response
        Ok(Response::builder()
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, *")
            .header(ACCESS_CONTROL_ALLOW_METHODS, methods)
            .header(CONTENT_LENGTH, "0")
            .status(StatusCode::OK)
            .body(Empty::new().map_err(|e| e.into()).boxed())?)
    } else {
        // Normal OPTIONS response
        Ok(Response::builder()
            .header(ALLOW, methods)
            .status(StatusCode::NO_CONTENT)
            .body(Empty::new().map_err(|e| e.into()).boxed())?)
    }
}

pub async fn handle_hash(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, HEAD, GET, DELETE");
    }

    // HEAD, GET, DELETE
    let p = request.uri().path();
    let hashstr: String = p.chars().skip(1).take(64).collect();
    let hash = match HashOutput::from_hex(&hashstr) {
        Ok(h) => h,
        Err(e) => return error_response(e),
    };

    let metadata = GLOBALS.filestore.get().unwrap().metadata(hash).await?;

    match request.method() {
        &Method::HEAD => Ok(Response::builder()
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(CONTENT_LENGTH, format!("{}", metadata.len()))
            .status(StatusCode::OK)
            .body(Empty::new().map_err(|e| e.into()).boxed())?),
        &Method::GET => {
            let body = GLOBALS.filestore.get().unwrap().retrieve(hash).await?;
            Ok(Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(CONTENT_LENGTH, format!("{}", metadata.len()))
                .status(StatusCode::OK)
                .body(body)?)
        }
        &Method::DELETE => {
            let auth_data = verify_auth(&request)?;
            if auth_data.verb != Some(AuthVerb::Delete) {
                return Err(ChorusError::BlossomAuthFailure(
                    "Delete was not authorized".to_string(),
                )
                .into());
            }

            GLOBALS.filestore.get().unwrap().delete(hash).await?;
            Ok(Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(CONTENT_LENGTH, "0")
                .status(StatusCode::OK)
                .body(Empty::new().map_err(|e| e.into()).boxed())?)
        }
        _ => Ok(Response::builder()
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(CONTENT_LENGTH, "0")
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Empty::new().map_err(|e| e.into()).boxed())?),
    }
}

pub async fn handle_upload(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, HEAD, PUT");
    }

    let auth_data = verify_auth(&request)?;
    if auth_data.verb != Some(AuthVerb::Upload) {
        return Err(
            ChorusError::BlossomAuthFailure("Upload was not authorized".to_string()).into(),
        );
    }

    match request.method() {
        &Method::HEAD => Ok(Response::builder()
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(CONTENT_LENGTH, "0")
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(Empty::new().map_err(|e| e.into()).boxed())?),
        &Method::PUT => {
            let expected_hash = auth_data.hash.map(|bytes| HashOutput::from_bytes(bytes));
            if expected_hash.is_none() {
                return Err(ChorusError::BlossomAuthFailure(
                    "Put requires an expected hash value x tag in the authorization event"
                        .to_string(),
                )
                .into());
            }

            let uri = request.uri().to_owned();

            let (size, hash) = GLOBALS
                .filestore
                .get()
                .unwrap()
                .store(
                    request.into_body().map_err(|e| e.into()).boxed(),
                    expected_hash,
                )
                .await?;

            let uri = {
                let mut parts = GLOBALS.config.read().uri_parts(uri, true)?;
                parts.path_and_query = Some(http::uri::PathAndQuery::from_maybe_shared(format!(
                    "/{}",
                    hash
                ))?);
                http::Uri::from_parts(parts)?
            };

            let blob_descriptor = BlobDescriptor {
                url: format!("{}", uri),
                sha256: format!("{}", hash),
                size,
                uploaded: pocket_types::Time::now().as_u64(),
            };

            let descriptor_json_string = serde_json::to_string(&blob_descriptor)?;
            let body_bytes = descriptor_json_string.into_bytes();
            let len = body_bytes.len();
            let body = Full::new(Bytes::from(body_bytes))
                .map_err(|e| e.into())
                .boxed();

            Ok(Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(CONTENT_LENGTH, format!("{}", len))
                .header(CONTENT_TYPE, "application/json")
                .status(StatusCode::OK)
                .body(body)?)
        }
        _ => Ok(Response::builder()
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(CONTENT_LENGTH, "0")
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Empty::new().map_err(|e| e.into()).boxed())?),
    }
}

pub async fn handle_list(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, GET");
    }

    let _auth_data = verify_auth(&request)?;

    unimplemented!()
}

pub async fn handle_mirror(
    request: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, PUT");
    }

    let _auth_data = verify_auth(&request)?;

    unimplemented!()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    // type: String
    pub uploaded: u64,
}
