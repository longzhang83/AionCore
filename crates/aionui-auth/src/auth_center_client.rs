use axum::http::{HeaderMap, header};
use base64::Engine as _;
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, get_current_timestamp};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use aionui_api_types::AuthConfigResponse;

use crate::auth_center_tokens::{AuthCenterTokenResponse, AuthCenterUserTokenBundle, bundle_from_token_response};
use crate::error::AuthCenterError;

const DEFAULT_APP_CODE: &str = "agent";
const BASE_OIDC_SCOPES: [&str; 3] = ["openid", "profile", "email"];
pub const AUTH_CENTER_PROVIDER: &str = "rsm-auth-center";
const STATE_TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct RsmAuthConfig {
    pub enabled: bool,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    /// Additional scopes appended to the fixed OIDC identity scopes.
    pub additional_scopes: Vec<String>,
    pub app_code: String,
    pub internal_base_url: Option<String>,
    pub internal_token: Option<String>,
}

impl RsmAuthConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: env_bool_any(&["RSM_AUTH_ENABLED", "AUTH_CENTER_ENABLED"]),
            issuer: env_non_empty_any(&["RSM_AUTH_ISSUER", "AUTH_CENTER_ISSUER"]),
            client_id: env_non_empty_any(&["RSM_AUTH_CLIENT_ID", "AUTH_CENTER_CLIENT_ID"]),
            client_secret: env_non_empty_any(&["RSM_AUTH_CLIENT_SECRET", "AUTH_CENTER_CLIENT_SECRET"]),
            redirect_uri: env_non_empty_any(&["RSM_AUTH_REDIRECT_URI", "AUTH_CENTER_REDIRECT_URI"]),
            additional_scopes: env_non_empty_any(&["RSM_AUTH_ADDITIONAL_SCOPES", "AUTH_CENTER_ADDITIONAL_SCOPES"])
                .map(|value| normalize_additional_scopes(&value))
                .unwrap_or_default(),
            app_code: env_non_empty_any(&["RSM_AUTH_APP_CODE", "AUTH_CENTER_APP_CODE"])
                .unwrap_or_else(|| DEFAULT_APP_CODE.to_owned()),
            internal_base_url: env_non_empty_any(&["AUTH_CENTER_INTERNAL_BASE_URL", "RSM_AUTH_INTERNAL_BASE_URL"]),
            internal_token: env_non_empty_any(&["AUTH_CENTER_INTERNAL_TOKEN", "RSM_AUTH_INTERNAL_TOKEN"]),
        }
    }

    pub fn public_response(&self) -> AuthConfigResponse {
        AuthConfigResponse {
            success: true,
            rsm_auth_enabled: self.is_oidc_ready(),
            rsm_auth_issuer: self.issuer.clone(),
            rsm_auth_client_id: self.client_id.clone(),
            rsm_auth_app_code: self.app_code.clone(),
            local_login_enabled: true,
        }
    }

    fn require_oidc_ready(&self) -> Result<ReadyOidcConfig<'_>, AuthCenterError> {
        if !self.enabled {
            return Err(AuthCenterError::NotFound("RSM Auth Center is disabled".into()));
        }

        let issuer = self
            .issuer
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| AuthCenterError::Internal("RSM_AUTH_ISSUER or AUTH_CENTER_ISSUER is required".into()))?;
        let client_id = self.client_id.as_deref().filter(|v| !v.is_empty()).ok_or_else(|| {
            AuthCenterError::Internal("RSM_AUTH_CLIENT_ID or AUTH_CENTER_CLIENT_ID is required".into())
        })?;
        let client_secret = self.client_secret.as_deref().unwrap_or("");

        Ok(ReadyOidcConfig {
            issuer,
            client_id,
            client_secret,
            redirect_uri: self.redirect_uri.as_deref(),
            additional_scopes: &self.additional_scopes,
            app_code: &self.app_code,
        })
    }

    fn require_directory_ready(&self) -> Result<ReadyDirectoryConfig<'_>, AuthCenterError> {
        if !self.enabled {
            return Err(AuthCenterError::NotFound("RSM Auth Center is disabled".into()));
        }

        let base_url = self
            .internal_base_url
            .as_deref()
            .or(self.issuer.as_deref())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AuthCenterError::Internal("AUTH_CENTER_INTERNAL_BASE_URL or AUTH_CENTER_ISSUER is required".into())
            })?;
        let internal_token = self
            .internal_token
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AuthCenterError::Internal("AUTH_CENTER_INTERNAL_TOKEN or RSM_AUTH_INTERNAL_TOKEN is required".into())
            })?;

        Ok(ReadyDirectoryConfig {
            base_url,
            internal_token,
            app_code: &self.app_code,
        })
    }

    fn is_oidc_ready(&self) -> bool {
        self.enabled
            && self.issuer.as_deref().is_some_and(|v| !v.is_empty())
            && self.client_id.as_deref().is_some_and(|v| !v.is_empty())
    }
}

struct ReadyOidcConfig<'a> {
    issuer: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    redirect_uri: Option<&'a str>,
    additional_scopes: &'a [String],
    app_code: &'a str,
}

struct ReadyDirectoryConfig<'a> {
    base_url: &'a str,
    internal_token: &'a str,
    app_code: &'a str,
}

#[derive(Debug, Clone)]
struct StoredLoginState {
    code_verifier: String,
    return_to: String,
    redirect_uri: String,
    nonce: String,
    created_at_ms: i64,
}

#[derive(Debug, Default)]
pub struct RsmOidcStateStore {
    states: DashMap<String, StoredLoginState>,
}

impl RsmOidcStateStore {
    pub fn new() -> Self {
        Self { states: DashMap::new() }
    }

    fn create(&self, return_to: String, redirect_uri: String) -> (String, String, String) {
        let state = random_url_token(32);
        let code_verifier = random_url_token(48);
        let nonce = random_url_token(32);
        self.states.insert(
            state.clone(),
            StoredLoginState {
                code_verifier: code_verifier.clone(),
                return_to,
                redirect_uri,
                nonce: nonce.clone(),
                created_at_ms: aionui_common::now_ms(),
            },
        );
        (state, code_verifier, nonce)
    }

    fn consume(&self, state: &str) -> Result<StoredLoginState, AuthCenterError> {
        let (_, stored) = self
            .states
            .remove(state)
            .ok_or_else(|| AuthCenterError::BadRequest("Invalid or expired OIDC state".into()))?;

        if aionui_common::now_ms().saturating_sub(stored.created_at_ms) > STATE_TTL_MS {
            return Err(AuthCenterError::BadRequest("Invalid or expired OIDC state".into()));
        }

        Ok(stored)
    }
}

#[derive(Debug, Deserialize)]
pub struct RsmOidcLoginQuery {
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RsmOidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthCenterLoginIdentity {
    pub sub: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub departments: Vec<String>,
    pub auth_source: String,
    pub app_code: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DirectoryUser {
    pub id: String,
    #[serde(default, alias = "tenantId", alias = "tenant_id")]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, alias = "displayName", alias = "display_name", alias = "name")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub mobile: Option<String>,
    #[serde(default)]
    pub position: Option<String>,
    #[serde(
        default,
        alias = "positionSort",
        alias = "position_sort",
        alias = "sortOrder",
        alias = "sort_order"
    )]
    pub position_sort: Option<i64>,
    #[serde(default, alias = "jobLevel", alias = "job_level")]
    pub job_level: Option<String>,
    #[serde(default, alias = "jobLevelCn", alias = "job_level_cn")]
    pub job_level_cn: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub departments: Vec<String>,
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, alias = "appRoles", alias = "app_roles")]
    pub app_roles: Option<Value>,
    #[serde(default, alias = "isAdmin", alias = "is_admin")]
    pub is_admin: Option<bool>,
    #[serde(default)]
    pub admin: Option<bool>,
    #[serde(default, alias = "updatedAt", alias = "updated_at")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DirectoryDepartment {
    pub id: String,
    #[serde(default, alias = "tenantId", alias = "tenant_id")]
    pub tenant_id: Option<String>,
    #[serde(default, alias = "parentId", alias = "parent_id")]
    pub parent_id: Option<String>,
    pub name: String,
    #[serde(default, alias = "externalId", alias = "external_id")]
    pub external_id: Option<String>,
    #[serde(default)]
    pub sort: i64,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "updatedAt", alias = "updated_at")]
    pub updated_at: Option<String>,
}

#[derive(Clone)]
pub struct AuthCenterProtocolClient {
    http_client: reqwest::Client,
}

impl AuthCenterProtocolClient {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }

    pub async fn build_login_redirect(
        &self,
        config: &RsmAuthConfig,
        store: &RsmOidcStateStore,
        headers: &HeaderMap,
        query: RsmOidcLoginQuery,
    ) -> Result<String, AuthCenterError> {
        let ready = config.require_oidc_ready()?;
        let discovery = self.discover(ready.issuer).await?;
        validate_discovered_issuer(&discovery, ready.issuer)?;

        let return_to = sanitize_return_to(query.return_to.as_deref());
        let redirect_uri = match ready.redirect_uri {
            Some(value) => value.to_owned(),
            None => callback_url(headers)?,
        };
        let (state, code_verifier, nonce) = store.create(return_to, redirect_uri.clone());
        let code_challenge = pkce_challenge(&code_verifier);
        let scopes = authorization_scopes(ready.additional_scopes);

        let mut url = Url::parse(&discovery.authorization_endpoint)
            .map_err(|e| AuthCenterError::BadGateway(format!("Invalid authorization endpoint: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", ready.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(url.to_string())
    }

    pub async fn exchange_callback(
        &self,
        config: &RsmAuthConfig,
        store: &RsmOidcStateStore,
        query: RsmOidcCallbackQuery,
    ) -> Result<(String, AuthCenterLoginIdentity, AuthCenterUserTokenBundle), AuthCenterError> {
        if let Some(error) = query.error {
            let detail = query.error_description.unwrap_or(error);
            return Err(AuthCenterError::Unauthorized(format!(
                "OIDC authorization failed: {detail}"
            )));
        }

        let ready = config.require_oidc_ready()?;
        let code = query
            .code
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| AuthCenterError::BadRequest("Missing OIDC code".into()))?;
        let state = query
            .state
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| AuthCenterError::BadRequest("Missing OIDC state".into()))?;

        let stored = store.consume(state)?;
        let discovery = self.discover(ready.issuer).await?;
        validate_discovered_issuer(&discovery, ready.issuer)?;

        let token = self.exchange_token(&discovery, &ready, code, &stored).await?;
        let id_claims = self
            .validate_id_token(
                &discovery,
                ready.issuer,
                ready.client_id,
                token.id_token.as_deref(),
                &stored.nonce,
            )
            .await?;
        let userinfo = self
            .fetch_userinfo(&discovery, ready.issuer, &token.access_token)
            .await?;
        if userinfo.sub != id_claims.sub {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token and userinfo subject mismatch".into(),
            ));
        }

        if !userinfo_has_app(userinfo.apps.as_ref(), ready.app_code) {
            return Err(AuthCenterError::Forbidden(format!(
                "RSM Auth Center user is not allowed for app '{}'",
                ready.app_code
            )));
        }

        let identity = AuthCenterLoginIdentity {
            sub: userinfo.sub.clone(),
            username: username_from_userinfo(&userinfo),
            display_name: userinfo.name.clone(),
            email: userinfo.email.clone(),
            mobile: userinfo.mobile.clone(),
            departments: userinfo.departments.clone().unwrap_or_default(),
            auth_source: userinfo
                .auth_source
                .clone()
                .unwrap_or_else(|| AUTH_CENTER_PROVIDER.to_owned()),
            app_code: ready.app_code.to_owned(),
            is_admin: userinfo_is_admin(&userinfo, ready.app_code),
        };

        let bundle = bundle_from_token_response(token, aionui_common::now_ms());

        Ok((stored.return_to, identity, bundle))
    }

    pub async fn list_directory_users(
        &self,
        config: &RsmAuthConfig,
        since_ms: Option<i64>,
    ) -> Result<Vec<DirectoryUser>, AuthCenterError> {
        let value = self.fetch_directory(config, "users", since_ms).await?;
        decode_directory_users(value)
    }

    pub async fn list_directory_departments(
        &self,
        config: &RsmAuthConfig,
        since_ms: Option<i64>,
    ) -> Result<Vec<DirectoryDepartment>, AuthCenterError> {
        let value = self.fetch_directory(config, "departments", since_ms).await?;
        decode_directory_departments(value)
    }

    async fn discover(&self, issuer: &str) -> Result<OidcDiscovery, AuthCenterError> {
        let issuer = issuer.trim_end_matches('/');
        let url = format!("{issuer}/.well-known/openid-configuration");
        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("Failed to discover RSM Auth Center: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthCenterError::BadGateway(format!(
                "RSM Auth Center discovery failed with status {}",
                resp.status()
            )));
        }
        resp.json::<OidcDiscovery>()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("Invalid RSM Auth Center discovery response: {e}")))
    }

    async fn exchange_token(
        &self,
        discovery: &OidcDiscovery,
        config: &ReadyOidcConfig<'_>,
        code: &str,
        stored: &StoredLoginState,
    ) -> Result<AuthCenterTokenResponse, AuthCenterError> {
        let form = TokenExchangeForm {
            grant_type: "authorization_code",
            code,
            redirect_uri: &stored.redirect_uri,
            client_id: config.client_id,
            client_secret: config.client_secret,
            code_verifier: &stored.code_verifier,
        };

        let resp = self
            .http_client
            .post(&discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("RSM Auth Center token exchange failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthCenterError::Unauthorized(format!(
                "RSM Auth Center token exchange failed with status {}",
                resp.status()
            )));
        }

        resp.json::<AuthCenterTokenResponse>()
            .await
            .map_err(|e| AuthCenterError::Unauthorized(format!("Invalid RSM Auth Center token response: {e}")))
    }

    async fn validate_id_token(
        &self,
        discovery: &OidcDiscovery,
        issuer: &str,
        client_id: &str,
        id_token: Option<&str>,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, AuthCenterError> {
        let id_token = id_token
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthCenterError::Unauthorized("RSM Auth Center token response missing id_token".into()))?;
        let header = decode_header(id_token)
            .map_err(|e| AuthCenterError::Unauthorized(format!("Invalid RSM Auth Center id_token header: {e}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token must use RS256".into(),
            ));
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthCenterError::Unauthorized("RSM Auth Center id_token missing kid".into()))?;

        let jwks = self.fetch_jwks(&discovery.jwks_uri).await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|key| {
                key.kid == kid
                    && key.kty == "RSA"
                    && key.alg.as_deref().unwrap_or("RS256") == "RS256"
                    && key.use_.as_deref().unwrap_or("sig") == "sig"
            })
            .ok_or_else(|| AuthCenterError::Unauthorized("RSM Auth Center signing key not found in JWKS".into()))?;
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| AuthCenterError::Unauthorized(format!("Invalid RSM Auth Center JWKS key: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| AuthCenterError::Unauthorized(format!("Invalid RSM Auth Center id_token: {e}")))?;
        let claims = token_data.claims;

        if claims.iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token issuer mismatch".into(),
            ));
        }
        if claims.token_use.as_deref().is_some_and(|value| value != "id") {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token token_use mismatch".into(),
            ));
        }
        let token_nonce = claims.nonce.as_deref().or(claims.jti.as_deref());
        if token_nonce != Some(expected_nonce) {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token nonce mismatch".into(),
            ));
        }
        let now = get_current_timestamp();
        if claims.iat > now.saturating_add(300) || claims.iat > claims.exp {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center id_token issued-at is invalid".into(),
            ));
        }

        Ok(claims)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<Jwks, AuthCenterError> {
        let resp = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("Failed to fetch RSM Auth Center JWKS: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthCenterError::BadGateway(format!(
                "RSM Auth Center JWKS failed with status {}",
                resp.status()
            )));
        }
        resp.json::<Jwks>()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("Invalid RSM Auth Center JWKS response: {e}")))
    }

    async fn fetch_userinfo(
        &self,
        discovery: &OidcDiscovery,
        issuer: &str,
        access_token: &str,
    ) -> Result<UserInfo, AuthCenterError> {
        let resp = self
            .http_client
            .get(&discovery.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("RSM Auth Center userinfo failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthCenterError::Unauthorized(format!(
                "RSM Auth Center userinfo failed with status {}",
                resp.status()
            )));
        }

        let userinfo = resp
            .json::<UserInfo>()
            .await
            .map_err(|e| AuthCenterError::Unauthorized(format!("Invalid RSM Auth Center userinfo response: {e}")))?;
        if userinfo.sub.trim().is_empty() {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center userinfo missing sub".into(),
            ));
        }
        if let Some(actual) = userinfo.iss.as_deref()
            && actual.trim_end_matches('/') != issuer.trim_end_matches('/')
        {
            return Err(AuthCenterError::Unauthorized(
                "RSM Auth Center userinfo issuer mismatch".into(),
            ));
        }
        Ok(userinfo)
    }

    async fn fetch_directory(
        &self,
        config: &RsmAuthConfig,
        resource: &str,
        since_ms: Option<i64>,
    ) -> Result<Value, AuthCenterError> {
        let ready = config.require_directory_ready()?;
        let base = ready.base_url.trim_end_matches('/');
        let mut url = Url::parse(&format!(
            "{base}/internal/directory/apps/{}/{}",
            ready.app_code, resource
        ))
        .map_err(|e| AuthCenterError::Internal(format!("Invalid RSM Auth Center directory endpoint config: {e}")))?;
        if let Some(since_ms) = since_ms {
            url.query_pairs_mut()
                .append_pair("since", &timestamp_ms_to_rfc3339(since_ms)?);
        }

        let resp = self
            .http_client
            .get(url)
            .bearer_auth(ready.internal_token)
            .send()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("RSM Auth Center directory request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AuthCenterError::BadGateway(format!(
                "RSM Auth Center directory request failed with status {}",
                resp.status()
            )));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| AuthCenterError::BadGateway(format!("Invalid RSM Auth Center directory response: {e}")))
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    kid: String,
    #[serde(default)]
    alg: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    exp: u64,
    #[serde(default)]
    iat: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    token_use: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    sub: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    mobile: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default, alias = "display_name")]
    name: Option<String>,
    #[serde(default)]
    departments: Option<Vec<String>>,
    #[serde(default)]
    auth_source: Option<String>,
    #[serde(default)]
    apps: Option<Value>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, alias = "appRoles", alias = "app_roles")]
    app_roles: Option<Value>,
    #[serde(default, alias = "isAdmin", alias = "is_admin")]
    is_admin: Option<bool>,
    #[serde(default)]
    admin: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TokenExchangeForm<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    code_verifier: &'a str,
}

fn decode_directory_users(value: Value) -> Result<Vec<DirectoryUser>, AuthCenterError> {
    match value {
        Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| AuthCenterError::BadGateway(format!("Invalid RSM Auth Center directory users response: {e}"))),
        Value::Object(map) => {
            let selected = map
                .get("list")
                .or_else(|| map.get("users"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            serde_json::from_value(selected).map_err(|e| {
                AuthCenterError::BadGateway(format!("Invalid RSM Auth Center directory users response: {e}"))
            })
        }
        _ => Err(AuthCenterError::BadGateway(
            "Invalid RSM Auth Center directory users response".into(),
        )),
    }
}

fn decode_directory_departments(value: Value) -> Result<Vec<DirectoryDepartment>, AuthCenterError> {
    match value {
        Value::Array(_) => serde_json::from_value(value).map_err(|e| {
            AuthCenterError::BadGateway(format!("Invalid RSM Auth Center directory departments response: {e}"))
        }),
        Value::Object(map) => {
            let selected = map
                .get("list")
                .or_else(|| map.get("departments"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            serde_json::from_value(selected).map_err(|e| {
                AuthCenterError::BadGateway(format!("Invalid RSM Auth Center directory departments response: {e}"))
            })
        }
        _ => Err(AuthCenterError::BadGateway(
            "Invalid RSM Auth Center directory departments response".into(),
        )),
    }
}

fn validate_discovered_issuer(discovery: &OidcDiscovery, expected: &str) -> Result<(), AuthCenterError> {
    if let Some(issuer) = discovery.issuer.as_deref()
        && issuer.trim_end_matches('/') != expected.trim_end_matches('/')
    {
        return Err(AuthCenterError::Unauthorized("RSM Auth Center issuer mismatch".into()));
    }
    Ok(())
}

fn normalize_additional_scopes(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

fn authorization_scopes(additional_scopes: &[String]) -> String {
    let mut scopes = BASE_OIDC_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect::<Vec<_>>();
    for scope in additional_scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    scopes.join(" ")
}

fn callback_url(headers: &HeaderMap) -> Result<String, AuthCenterError> {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| AuthCenterError::BadRequest("Missing Host header".into()))?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|v| matches!(*v, "http" | "https"))
        .unwrap_or("http");
    Ok(format!("{proto}://{host}/api/auth/oidc/callback"))
}

fn sanitize_return_to(value: Option<&str>) -> String {
    match value {
        Some(v) if v.starts_with('/') && !v.starts_with("//") => v.to_owned(),
        _ => "/".to_owned(),
    }
}

fn userinfo_has_app(apps: Option<&Value>, app_code: &str) -> bool {
    let Some(Value::Array(items)) = apps else {
        return false;
    };

    items.iter().any(|item| match item {
        Value::String(value) => value == app_code,
        Value::Object(map) => ["code", "app_code", "appCode", "id"]
            .iter()
            .filter_map(|key| map.get(*key))
            .any(|value| value.as_str() == Some(app_code)),
        _ => false,
    })
}

pub fn directory_user_is_admin(user: &DirectoryUser, app_code: &str) -> bool {
    user.is_admin.unwrap_or(false)
        || user.admin.unwrap_or(false)
        || roles_have_admin(&user.roles)
        || value_has_app_admin(user.app_roles.as_ref(), app_code)
}

fn userinfo_is_admin(userinfo: &UserInfo, app_code: &str) -> bool {
    userinfo.is_admin.unwrap_or(false)
        || userinfo.admin.unwrap_or(false)
        || roles_have_admin(&userinfo.roles)
        || value_has_app_admin(userinfo.app_roles.as_ref(), app_code)
        || apps_have_app_admin(userinfo.apps.as_ref(), app_code)
}

fn roles_have_admin(roles: &[String]) -> bool {
    roles.iter().any(|role| role_is_admin(role))
}

fn role_is_admin(role: &str) -> bool {
    let normalized = role
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(normalized.as_str(), "admin" | "administrator" | "superadmin" | "owner")
}

fn value_has_admin_role(value: &Value) -> bool {
    match value {
        Value::String(role) => role_is_admin(role),
        Value::Bool(is_admin) => *is_admin,
        Value::Array(items) => items.iter().any(value_has_admin_role),
        Value::Object(map) => {
            ["isAdmin", "is_admin", "admin"]
                .iter()
                .filter_map(|key| map.get(*key))
                .any(|value| value.as_bool() == Some(true))
                || ["role", "roles", "appRole", "appRoles", "app_role", "app_roles"]
                    .iter()
                    .filter_map(|key| map.get(*key))
                    .any(value_has_admin_role)
        }
        _ => false,
    }
}

fn value_has_app_admin(value: Option<&Value>, app_code: &str) -> bool {
    match value {
        Some(Value::Object(map)) => {
            map.get(app_code).is_some_and(value_has_admin_role)
                || map
                    .values()
                    .any(|entry| value_matches_app(entry, app_code) && value_has_admin_role(entry))
        }
        Some(Value::Array(items)) => items
            .iter()
            .any(|entry| value_matches_app(entry, app_code) && value_has_admin_role(entry)),
        Some(_) => false,
        None => false,
    }
}

fn apps_have_app_admin(apps: Option<&Value>, app_code: &str) -> bool {
    let Some(Value::Array(items)) = apps else {
        return false;
    };
    items
        .iter()
        .any(|entry| value_matches_app(entry, app_code) && value_has_admin_role(entry))
}

fn value_matches_app(value: &Value, app_code: &str) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    ["code", "app_code", "appCode", "id"]
        .iter()
        .filter_map(|key| map.get(*key))
        .any(|value| value.as_str() == Some(app_code))
}

fn username_from_userinfo(userinfo: &UserInfo) -> String {
    let raw = userinfo
        .preferred_username
        .as_deref()
        .or_else(|| userinfo.email.as_deref().and_then(|v| v.split('@').next()))
        .or(userinfo.name.as_deref())
        .unwrap_or(&userinfo.sub);
    sanitize_username(raw, &userinfo.sub)
}

pub fn sanitize_username(raw: &str, fallback_sub: &str) -> String {
    let mut out = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    out = out.trim_matches(['-', '_']).to_owned();
    if out.len() < 3 {
        out = format!("rsm_{}", fallback_sub.chars().take(16).collect::<String>());
    }
    out = out
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    out.chars().take(32).collect()
}

pub fn directory_status_to_local_status(status: Option<&str>) -> &'static str {
    match status.unwrap_or("active").trim().to_ascii_lowercase().as_str() {
        "" | "active" | "enabled" | "enable" | "1" => "active",
        _ => "disabled",
    }
}

pub fn timestamp_rfc3339_to_ms(value: Option<&str>) -> Option<i64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|datetime| datetime.timestamp_millis())
}

fn timestamp_ms_to_rfc3339(value: i64) -> Result<String, AuthCenterError> {
    let Some(datetime) = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(value) else {
        return Err(AuthCenterError::BadRequest("Invalid directory sync timestamp".into()));
    };
    Ok(datetime.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn random_url_token(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn env_non_empty_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn env_bool_any(names: &[&str]) -> bool {
    names.iter().any(|name| {
        std::env::var(name)
            .ok()
            .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn directory_user_admin_mapping_is_exact_and_app_scoped() {
        let agent_admin: DirectoryUser = serde_json::from_value(json!({
            "id": "user-1",
            "username": "alice",
            "appRoles": {
                "agent": ["admin"]
            }
        }))
        .unwrap();
        assert!(directory_user_is_admin(&agent_admin, "agent"));

        let other_app_admin: DirectoryUser = serde_json::from_value(json!({
            "id": "user-2",
            "username": "bob",
            "appRoles": {
                "crm": ["admin"]
            }
        }))
        .unwrap();
        assert!(!directory_user_is_admin(&other_app_admin, "agent"));

        let not_admin: DirectoryUser = serde_json::from_value(json!({
            "id": "user-3",
            "username": "charlie",
            "roles": ["not_admin", "admin_readonly"]
        }))
        .unwrap();
        assert!(!directory_user_is_admin(&not_admin, "agent"));

        let unscoped_app_roles: DirectoryUser = serde_json::from_value(json!({
            "id": "user-4",
            "username": "dora",
            "appRoles": ["admin"]
        }))
        .unwrap();
        assert!(!directory_user_is_admin(&unscoped_app_roles, "agent"));
    }

    #[test]
    fn userinfo_admin_mapping_accepts_explicit_app_admin_claim() {
        let userinfo = UserInfo {
            sub: "auth-user-1".to_owned(),
            iss: None,
            email: None,
            mobile: None,
            preferred_username: Some("alice".to_owned()),
            name: None,
            departments: None,
            auth_source: None,
            apps: Some(json!([
                {
                    "code": "agent",
                    "role": "administrator"
                }
            ])),
            roles: Vec::new(),
            app_roles: None,
            is_admin: None,
            admin: None,
        };

        assert!(userinfo_is_admin(&userinfo, "agent"));
        assert!(!userinfo_is_admin(&userinfo, "crm"));
    }
}
