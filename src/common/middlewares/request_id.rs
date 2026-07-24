use axum::{extract::Request, http::HeaderName};
use tower_http::request_id::{
  MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};

#[derive(Clone, Default)]
pub struct Id;

impl MakeRequestId for Id {
  fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
    let id = uuid::Uuid::now_v7().to_string().parse().unwrap();
    Some(RequestId::new(id))
  }
}

/// Sets the 'x-request-id' header with a randomly generated UUID v7.
///
/// SetRequestId will not override request IDs if they are already present
/// on requests or responses.
pub fn request_id_layer() -> SetRequestIdLayer<Id> {
  let x_request_id = HeaderName::from_static("x-request-id");
  SetRequestIdLayer::new(x_request_id.clone(), Id)
}

/// Propagates 'x-request-id' header from the request to the response.
///
/// PropagateRequestId wont override request ids if its already
/// present on requests or responses.
pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
  let x_request_id = HeaderName::from_static("x-request-id");
  PropagateRequestIdLayer::new(x_request_id)
}
