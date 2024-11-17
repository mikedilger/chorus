use crate::error::{ChorusError, Error};
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ALLOW, CONTENT_LENGTH, ORIGIN,
    WWW_AUTHENTICATE,
};
use http::{Method, StatusCode};
//ACCEPT, AUTHORIZATION, CONTENT_TYPE, DATE, ETAG, ORIGIN
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};

pub async fn handle(request: &Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    match route(request).await {
        Ok(response) => Ok(response),
        Err(e) => match e.inner {
            ChorusError::SignalNotBlossom => Err(e),
            _ => error_response(e),
        },
    }
}

pub async fn route(request: &Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
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
    request: &Request<Incoming>,
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
    request: &Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, HEAD, GET, DELETE");
    }

    unimplemented!()
}

pub async fn handle_upload(
    request: &Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, HEAD, PUT");
    }

    unimplemented!()
}

pub async fn handle_list(
    request: &Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, GET");
    }

    unimplemented!()
}

pub async fn handle_mirror(
    request: &Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, Error>>, Error> {
    if matches!(request.method(), &Method::OPTIONS) {
        return options_response(request, "OPTIONS, PUT");
    }

    unimplemented!()
}
