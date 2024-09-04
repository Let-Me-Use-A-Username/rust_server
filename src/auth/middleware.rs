use std::future::{ready, Ready};

use actix_session::SessionExt;
use actix_web::{dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, http::Error};
use futures_util::future::LocalBoxFuture;


// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct SessionCookieMiddleware;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SessionCookieMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SessionCookieMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SessionCookieMiddlewareService { service }))
    }
}

pub struct SessionCookieMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SessionCookieMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = &self.service;

        let fut = async move {
            // Retrieve the session.
            let session = req.get_session();

            // Check if user is authenticated, you can add logic to check for user authentication here.
            if let Some(user_id) = session.get::<String>("user_id").ok().flatten() {
                // Set a custom session cookie name based on user_id
                let cookie_name = format!("session_{}", user_id);

                // Insert or modify cookie here. (this is a simplified example)
                let cookie = session.cookie().unwrap().clone();
                let mut cookie_builder = cookie.into_owned().into_owned();
                cookie_builder.name(cookie_name);
                session.add_cookie(cookie_builder.build())?;
            }

            svc.call(req).await
        };

        Box::pin(fut)
    }
}