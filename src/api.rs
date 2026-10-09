use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::{StatusCode, header, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::settle::{self, Adjacency, PersonId};

const INDEX_HTML: &str = include_str!("../static/index.html");

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
}

impl AppState {
    pub fn new(conn: Connection) -> Self {
        Self { db: Arc::new(Mutex::new(conn)), attempts: Arc::default() }
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub fn router(state: AppState) -> Router {
    // Routes that check passwords or create accounts; rate limited per client IP.
    let limited = Router::new()
        .route("/api/splitters", post(create_splitter))
        .route("/api/login", post(login))
        .route("/api/join", post(join))
        .route("/api/splitter/password", put(change_password))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit));

    Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .merge(limited)
        .route("/api/logout", post(logout))
        .route("/api/state", get(get_state))
        .route("/api/settings", put(update_settings))
        .route("/api/splitter/name", put(rename_splitter))
        .route("/api/splitter/invite", get(get_invite))
        .route("/api/persons", post(add_person))
        .route("/api/persons/{id}", put(rename_person).delete(delete_person))
        .route("/api/groups", post(add_group))
        .route("/api/groups/{id}", put(update_group).delete(delete_group))
        .route("/api/methods", post(add_method))
        .route("/api/methods/{id}", put(update_method).delete(delete_method))
        .route("/api/rates/{code}", put(set_rate).delete(delete_rate))
        .route("/api/bills", post(add_bill))
        .route("/api/bills/{id}", put(update_bill).delete(delete_bill))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Errors

pub struct AppError(StatusCode, String);

type ApiResult<T> = Result<T, AppError>;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(f, _) = &e {
            match f.extended_code {
                rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY => {
                    return conflict("That name is already taken");
                }
                rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY => {
                    return conflict("It is still referenced elsewhere");
                }
                _ => {}
            }
        }
        eprintln!("database error: {e}");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".into())
    }
}

fn bad(msg: impl Into<String>) -> AppError {
    AppError(StatusCode::BAD_REQUEST, msg.into())
}

fn conflict(msg: impl Into<String>) -> AppError {
    AppError(StatusCode::CONFLICT, msg.into())
}

fn not_found() -> AppError {
    AppError(StatusCode::NOT_FOUND, "Not found".into())
}

fn unauthorized(msg: &str) -> AppError {
    AppError(StatusCode::UNAUTHORIZED, msg.into())
}

// ---------------------------------------------------------------------------
// Rate limiting

const RATE_LIMIT_MAX: u32 = 10;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Allows `RATE_LIMIT_MAX` requests per `RATE_LIMIT_WINDOW` per client. The client
/// is identified by the `X-Forwarded-For` header set by the reverse proxy, so the
/// server must only be reachable through that proxy.
async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let client = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let now = Instant::now();
    {
        let mut attempts = st.attempts.lock().unwrap_or_else(|e| e.into_inner());
        if attempts.len() > 10_000 {
            attempts.retain(|_, (_, start)| now.duration_since(*start) < RATE_LIMIT_WINDOW);
        }
        let entry = attempts.entry(client).or_insert((0, now));
        if now.duration_since(entry.1) >= RATE_LIMIT_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 > RATE_LIMIT_MAX {
            return AppError(StatusCode::TOO_MANY_REQUESTS, "Too many attempts, please wait a minute".into())
                .into_response();
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Authentication

/// The splitter the request's bearer token is logged into.
pub struct Auth {
    splitter_id: i64,
    token: String,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| unauthorized("Not logged in"))?
            .to_string();
        let splitter_id = state
            .db()
            .query_row("SELECT splitter_id FROM sessions WHERE token = ?1", [&token], |r| r.get(0))
            .optional()?
            .ok_or_else(|| unauthorized("Session expired, please log in again"))?;
        Ok(Auth { splitter_id, token })
    }
}

fn new_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn create_session(conn: &Connection, splitter_id: i64) -> ApiResult<String> {
    let token = new_token();
    conn.execute(
        "INSERT INTO sessions (token, splitter_id) VALUES (?1, ?2)",
        params![token, splitter_id],
    )?;
    Ok(token)
}

#[derive(Deserialize)]
struct CreateSplitter {
    name: String,
    password: String,
    base_currency: String,
}

#[derive(Deserialize)]
struct Login {
    name: String,
    password: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

async fn create_splitter(
    State(st): State<AppState>,
    Json(req): Json<CreateSplitter>,
) -> ApiResult<Json<TokenResponse>> {
    let name = clean_name(&req.name, "Splitter name")?;
    check_password(&req.password)?;
    let base = currency_code(&req.base_currency)?;
    let hash = hash_password(req.password).await?;

    let conn = st.db();
    conn.execute(
        "INSERT INTO splitters (name, password_hash, base_currency) VALUES (?1, ?2, ?3)",
        params![name, hash, base],
    )
    .map_err(name_taken)?;
    let token = create_session(&conn, conn.last_insert_rowid())?;
    Ok(Json(TokenResponse { token }))
}

async fn login(State(st): State<AppState>, Json(req): Json<Login>) -> ApiResult<Json<TokenResponse>> {
    let row: Option<(i64, String)> = st
        .db()
        .query_row(
            "SELECT id, password_hash FROM splitters WHERE name = ?1",
            [req.name.trim()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let wrong = || unauthorized("Wrong splitter name or password");
    let (id, hash) = row.ok_or_else(wrong)?;
    if !verify_password(req.password, hash).await {
        return Err(wrong());
    }
    let token = create_session(&st.db(), id)?;
    Ok(Json(TokenResponse { token }))
}

#[derive(Deserialize)]
struct Join {
    invite: String,
}

async fn join(State(st): State<AppState>, Json(req): Json<Join>) -> ApiResult<Json<TokenResponse>> {
    let conn = st.db();
    let id: i64 = conn
        .query_row("SELECT splitter_id FROM invites WHERE token = ?1", [&req.invite], |r| r.get(0))
        .optional()?
        .ok_or_else(|| unauthorized("This invite link is no longer valid"))?;
    let token = create_session(&conn, id)?;
    Ok(Json(TokenResponse { token }))
}

/// The splitter's invite token, created on first request.
async fn get_invite(State(st): State<AppState>, auth: Auth) -> ApiResult<Json<TokenResponse>> {
    let conn = st.db();
    conn.execute(
        "INSERT OR IGNORE INTO invites (token, splitter_id) VALUES (?1, ?2)",
        params![new_token(), auth.splitter_id],
    )?;
    let token = conn.query_row(
        "SELECT token FROM invites WHERE splitter_id = ?1",
        [auth.splitter_id],
        |r| r.get(0),
    )?;
    Ok(Json(TokenResponse { token }))
}

async fn logout(State(st): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    st.db().execute("DELETE FROM sessions WHERE token = ?1", [auth.token])?;
    Ok(StatusCode::NO_CONTENT)
}

fn check_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < 6 {
        return Err(bad("Password must be at least 6 characters"));
    }
    Ok(())
}

async fn hash_password(password: String) -> ApiResult<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default().hash_password(password.as_bytes()).map(|h| h.to_string())
    })
    .await
    .map_err(|_| bad("Hashing failed"))?
    .map_err(|_| bad("Hashing failed"))
}

async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

fn name_taken(e: rusqlite::Error) -> AppError {
    match AppError::from(e) {
        AppError(StatusCode::CONFLICT, _) => conflict("A splitter with that name already exists"),
        other => other,
    }
}

async fn rename_splitter(
    State(st): State<AppState>,
    auth: Auth,
    Json(req): Json<NameInput>,
) -> ApiResult<StatusCode> {
    let name = clean_name(&req.name, "Splitter name")?;
    st.db()
        .execute("UPDATE splitters SET name = ?1 WHERE id = ?2", params![name, auth.splitter_id])
        .map_err(name_taken)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}

/// Change the password, log out every other session and revoke the invite
/// link, so people who only knew the old password or link lose access.
async fn change_password(
    State(st): State<AppState>,
    auth: Auth,
    Json(req): Json<ChangePassword>,
) -> ApiResult<StatusCode> {
    check_password(&req.new_password)?;
    let old_hash: String = st.db().query_row(
        "SELECT password_hash FROM splitters WHERE id = ?1",
        [auth.splitter_id],
        |r| r.get(0),
    )?;
    if !verify_password(req.current_password, old_hash).await {
        return Err(bad("Current password is wrong"));
    }
    let hash = hash_password(req.new_password).await?;
    let mut conn = st.db();
    let tx = conn.transaction()?;
    tx.execute("UPDATE splitters SET password_hash = ?1 WHERE id = ?2", params![hash, auth.splitter_id])?;
    tx.execute(
        "DELETE FROM sessions WHERE splitter_id = ?1 AND token <> ?2",
        params![auth.splitter_id, auth.token],
    )?;
    tx.execute("DELETE FROM invites WHERE splitter_id = ?1", [auth.splitter_id])?;
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Validation helpers

fn clean_name(s: &str, what: &str) -> ApiResult<String> {
    let s = s.trim();
    if s.is_empty() {
        return Err(bad(format!("{what} must not be empty")));
    }
    if s.chars().count() > 80 {
        return Err(bad(format!("{what} is too long")));
    }
    Ok(s.to_string())
}

fn currency_code(s: &str) -> ApiResult<String> {
    let s = s.trim().to_uppercase();
    if s.len() == 3 && s.chars().all(|c| c.is_ascii_uppercase()) {
        Ok(s)
    } else {
        Err(bad("Currency must be a 3-letter code like EUR or DKK"))
    }
}

/// Fail with 404 unless row `id` of `table` belongs to the splitter.
fn ensure_owned(conn: &Connection, table: &str, splitter_id: i64, id: i64) -> ApiResult<()> {
    let found: Option<i64> = conn
        .query_row(
            &format!("SELECT 1 FROM {table} WHERE id = ?1 AND splitter_id = ?2"),
            params![id, splitter_id],
            |r| r.get(0),
        )
        .optional()?;
    found.map(|_| ()).ok_or_else(not_found)
}

fn ensure_persons(conn: &Connection, splitter_id: i64, ids: &[i64]) -> ApiResult<()> {
    for &id in ids {
        ensure_owned(conn, "persons", splitter_id, id).map_err(|_| bad(format!("Unknown person {id}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings, persons, currency rates

#[derive(Deserialize)]
struct Settings {
    base_currency: String,
}

async fn update_settings(
    State(st): State<AppState>,
    auth: Auth,
    Json(req): Json<Settings>,
) -> ApiResult<StatusCode> {
    let new_base = currency_code(&req.base_currency)?;
    let mut conn = st.db();
    let old_base: String = conn.query_row(
        "SELECT base_currency FROM splitters WHERE id = ?1",
        [auth.splitter_id],
        |r| r.get(0),
    )?;
    if new_base == old_base {
        return Ok(StatusCode::NO_CONTENT);
    }
    // Re-express all rates relative to the new base currency.
    let pivot: Option<f64> = conn
        .query_row(
            "SELECT rate FROM rates WHERE splitter_id = ?1 AND code = ?2",
            params![auth.splitter_id, new_base],
            |r| r.get(0),
        )
        .optional()?;
    let pivot = pivot.ok_or_else(|| {
        bad(format!("Set an exchange rate for {new_base} first, so existing rates can be converted"))
    })?;
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE rates SET rate = rate / ?1 WHERE splitter_id = ?2",
        params![pivot, auth.splitter_id],
    )?;
    tx.execute(
        "DELETE FROM rates WHERE splitter_id = ?1 AND code = ?2",
        params![auth.splitter_id, new_base],
    )?;
    tx.execute(
        "INSERT INTO rates (splitter_id, code, rate) VALUES (?1, ?2, ?3)",
        params![auth.splitter_id, old_base, 1.0 / pivot],
    )?;
    tx.execute(
        "UPDATE splitters SET base_currency = ?1 WHERE id = ?2",
        params![new_base, auth.splitter_id],
    )?;
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NameInput {
    name: String,
}

async fn add_person(
    State(st): State<AppState>,
    auth: Auth,
    Json(req): Json<NameInput>,
) -> ApiResult<StatusCode> {
    let name = clean_name(&req.name, "Name")?;
    st.db().execute(
        "INSERT INTO persons (splitter_id, name) VALUES (?1, ?2)",
        params![auth.splitter_id, name],
    )?;
    Ok(StatusCode::CREATED)
}

async fn rename_person(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<NameInput>,
) -> ApiResult<StatusCode> {
    let name = clean_name(&req.name, "Name")?;
    let conn = st.db();
    ensure_owned(&conn, "persons", auth.splitter_id, id)?;
    conn.execute("UPDATE persons SET name = ?1 WHERE id = ?2", params![name, id])?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_person(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    let conn = st.db();
    ensure_owned(&conn, "persons", auth.splitter_id, id)?;
    let used: i64 = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM bill_payers WHERE person_id = ?1)
              + (SELECT COUNT(*) FROM bill_shares WHERE person_id = ?1)",
        [id],
        |r| r.get(0),
    )?;
    if used > 0 {
        return Err(conflict("This person appears in bills; remove them from those bills first"));
    }
    conn.execute("DELETE FROM persons WHERE id = ?1", [id])?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RateInput {
    rate: f64,
}

async fn set_rate(
    State(st): State<AppState>,
    auth: Auth,
    Path(code): Path<String>,
    Json(req): Json<RateInput>,
) -> ApiResult<StatusCode> {
    let code = currency_code(&code)?;
    if !(req.rate.is_finite() && req.rate > 0.0) {
        return Err(bad("Rate must be a positive number"));
    }
    let conn = st.db();
    let base: String = conn.query_row(
        "SELECT base_currency FROM splitters WHERE id = ?1",
        [auth.splitter_id],
        |r| r.get(0),
    )?;
    if code == base {
        return Err(bad("The base currency always has rate 1"));
    }
    conn.execute(
        "INSERT INTO rates (splitter_id, code, rate) VALUES (?1, ?2, ?3)
         ON CONFLICT (splitter_id, code) DO UPDATE SET rate = excluded.rate",
        params![auth.splitter_id, code, req.rate],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_rate(
    State(st): State<AppState>,
    auth: Auth,
    Path(code): Path<String>,
) -> ApiResult<StatusCode> {
    st.db().execute(
        "DELETE FROM rates WHERE splitter_id = ?1 AND code = ?2",
        params![auth.splitter_id, code.to_uppercase()],
    )?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Person groups and payment methods: both are named sets of persons.

#[derive(Deserialize)]
struct SetInput {
    name: String,
    member_ids: Vec<i64>,
}

struct SetTables {
    table: &'static str,
    members: &'static str,
    fk: &'static str,
    what: &'static str,
}

const GROUPS: SetTables = SetTables {
    table: "person_groups",
    members: "person_group_members",
    fk: "group_id",
    what: "Group name",
};

const METHODS: SetTables = SetTables {
    table: "payment_methods",
    members: "payment_method_members",
    fk: "method_id",
    what: "Payment method name",
};

fn save_set(
    conn: &mut Connection,
    t: &SetTables,
    splitter_id: i64,
    id: Option<i64>,
    req: SetInput,
) -> ApiResult<StatusCode> {
    let name = clean_name(&req.name, t.what)?;
    let members: BTreeSet<i64> = req.member_ids.into_iter().collect();
    ensure_persons(conn, splitter_id, &members.iter().copied().collect::<Vec<_>>())?;
    if let Some(id) = id {
        ensure_owned(conn, t.table, splitter_id, id)?;
    }
    let tx = conn.transaction()?;
    let id = match id {
        Some(id) => {
            tx.execute(&format!("UPDATE {} SET name = ?1 WHERE id = ?2", t.table), params![name, id])?;
            tx.execute(&format!("DELETE FROM {} WHERE {} = ?1", t.members, t.fk), [id])?;
            id
        }
        None => {
            tx.execute(
                &format!("INSERT INTO {} (splitter_id, name) VALUES (?1, ?2)", t.table),
                params![splitter_id, name],
            )?;
            tx.last_insert_rowid()
        }
    };
    for m in members {
        tx.execute(
            &format!("INSERT INTO {} ({}, person_id) VALUES (?1, ?2)", t.members, t.fk),
            params![id, m],
        )?;
    }
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

fn delete_set(conn: &Connection, t: &SetTables, splitter_id: i64, id: i64) -> ApiResult<StatusCode> {
    ensure_owned(conn, t.table, splitter_id, id)?;
    conn.execute(&format!("DELETE FROM {} WHERE id = ?1", t.table), [id])?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_group(State(st): State<AppState>, auth: Auth, Json(req): Json<SetInput>) -> ApiResult<StatusCode> {
    save_set(&mut st.db(), &GROUPS, auth.splitter_id, None, req)
}

async fn update_group(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<SetInput>,
) -> ApiResult<StatusCode> {
    save_set(&mut st.db(), &GROUPS, auth.splitter_id, Some(id), req)
}

async fn delete_group(State(st): State<AppState>, auth: Auth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    delete_set(&st.db(), &GROUPS, auth.splitter_id, id)
}

async fn add_method(State(st): State<AppState>, auth: Auth, Json(req): Json<SetInput>) -> ApiResult<StatusCode> {
    save_set(&mut st.db(), &METHODS, auth.splitter_id, None, req)
}

async fn update_method(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<SetInput>,
) -> ApiResult<StatusCode> {
    save_set(&mut st.db(), &METHODS, auth.splitter_id, Some(id), req)
}

async fn delete_method(State(st): State<AppState>, auth: Auth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    delete_set(&st.db(), &METHODS, auth.splitter_id, id)
}

// ---------------------------------------------------------------------------
// Bills

#[derive(Deserialize)]
struct PayerInput {
    person_id: i64,
    /// Cents.
    amount: i64,
}

#[derive(Deserialize)]
struct ShareInput {
    person_id: i64,
    /// Ignored for `equal`, a share weight for `shares`, cents for `exact`.
    #[serde(default)]
    value: f64,
}

#[derive(Deserialize)]
struct BillInput {
    description: String,
    currency: String,
    date: Option<String>,
    payers: Vec<PayerInput>,
    split_mode: String,
    shares: Vec<ShareInput>,
}

struct PreparedBill {
    description: String,
    currency: String,
    date: Option<String>,
    split_mode: String,
    payers: Vec<(i64, i64)>,
    /// (person, weight, owed cents)
    shares: Vec<(i64, f64, i64)>,
}

fn prepare_bill(req: BillInput) -> ApiResult<PreparedBill> {
    let description = clean_name(&req.description, "Description")?;
    let currency = currency_code(&req.currency)?;
    let date = req.date.map(|d| d.trim().to_string()).filter(|d| !d.is_empty());

    let mut payers: BTreeMap<i64, i64> = BTreeMap::new();
    for p in &req.payers {
        if p.amount < 0 {
            return Err(bad("Paid amounts must not be negative"));
        }
        *payers.entry(p.person_id).or_default() += p.amount;
    }
    payers.retain(|_, a| *a > 0);
    let total: i64 = payers.values().sum();
    if total <= 0 {
        return Err(bad("Someone has to pay something"));
    }

    let mut seen = BTreeSet::new();
    if req.shares.is_empty() {
        return Err(bad("Choose who the bill is split between"));
    }
    if !req.shares.iter().all(|s| seen.insert(s.person_id)) {
        return Err(bad("A person appears twice in the split"));
    }
    let ids: Vec<i64> = req.shares.iter().map(|s| s.person_id).collect();
    let (weights, owed): (Vec<f64>, Vec<i64>) = match req.split_mode.as_str() {
        "equal" => {
            let w = vec![1.0; ids.len()];
            let o = settle::split_by_weights(total, &w);
            (w, o)
        }
        "shares" => {
            let w: Vec<f64> = req.shares.iter().map(|s| s.value).collect();
            if w.iter().any(|x| !x.is_finite() || *x < 0.0) || w.iter().sum::<f64>() <= 0.0 {
                return Err(bad("Shares must be non-negative and not all zero"));
            }
            let o = settle::split_by_weights(total, &w);
            (w, o)
        }
        "exact" => {
            let o: Vec<i64> = req.shares.iter().map(|s| s.value.round() as i64).collect();
            if o.iter().any(|x| *x < 0) {
                return Err(bad("Amounts must not be negative"));
            }
            let sum: i64 = o.iter().sum();
            if sum != total {
                return Err(bad(format!(
                    "The split amounts add up to {:.2} but {:.2} was paid",
                    sum as f64 / 100.0,
                    total as f64 / 100.0
                )));
            }
            (o.iter().map(|x| *x as f64).collect(), o)
        }
        _ => return Err(bad("Unknown split mode")),
    };
    let shares = ids.into_iter().zip(weights).zip(owed).map(|((p, w), o)| (p, w, o)).collect();
    Ok(PreparedBill {
        description,
        currency,
        date,
        split_mode: req.split_mode,
        payers: payers.into_iter().collect(),
        shares,
    })
}

fn save_bill(conn: &mut Connection, splitter_id: i64, id: Option<i64>, req: BillInput) -> ApiResult<StatusCode> {
    let b = prepare_bill(req)?;
    let people: Vec<i64> = b.payers.iter().map(|p| p.0).chain(b.shares.iter().map(|s| s.0)).collect();
    ensure_persons(conn, splitter_id, &people)?;
    if let Some(id) = id {
        ensure_owned(conn, "bills", splitter_id, id)?;
    }
    let tx = conn.transaction()?;
    let id = match id {
        Some(id) => {
            tx.execute(
                "UPDATE bills SET description = ?1, currency = ?2, date = ?3, split_mode = ?4 WHERE id = ?5",
                params![b.description, b.currency, b.date, b.split_mode, id],
            )?;
            tx.execute("DELETE FROM bill_payers WHERE bill_id = ?1", [id])?;
            tx.execute("DELETE FROM bill_shares WHERE bill_id = ?1", [id])?;
            id
        }
        None => {
            tx.execute(
                "INSERT INTO bills (splitter_id, description, currency, date, split_mode)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![splitter_id, b.description, b.currency, b.date, b.split_mode],
            )?;
            tx.last_insert_rowid()
        }
    };
    for (p, amount) in &b.payers {
        tx.execute(
            "INSERT INTO bill_payers (bill_id, person_id, amount) VALUES (?1, ?2, ?3)",
            params![id, p, amount],
        )?;
    }
    for (p, weight, owed) in &b.shares {
        tx.execute(
            "INSERT INTO bill_shares (bill_id, person_id, weight, owed) VALUES (?1, ?2, ?3, ?4)",
            params![id, p, weight, owed],
        )?;
    }
    tx.commit()?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_bill(State(st): State<AppState>, auth: Auth, Json(req): Json<BillInput>) -> ApiResult<StatusCode> {
    save_bill(&mut st.db(), auth.splitter_id, None, req)
}

async fn update_bill(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<BillInput>,
) -> ApiResult<StatusCode> {
    save_bill(&mut st.db(), auth.splitter_id, Some(id), req)
}

async fn delete_bill(State(st): State<AppState>, auth: Auth, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    let conn = st.db();
    ensure_owned(&conn, "bills", auth.splitter_id, id)?;
    conn.execute("DELETE FROM bills WHERE id = ?1", [id])?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Full state + computed summary

#[derive(Serialize)]
struct Person {
    id: i64,
    name: String,
}

#[derive(Serialize)]
struct NamedSet {
    id: i64,
    name: String,
    member_ids: Vec<i64>,
}

#[derive(Serialize)]
struct Rate {
    code: String,
    rate: f64,
}

#[derive(Serialize)]
struct Payer {
    person_id: i64,
    amount: i64,
}

#[derive(Serialize)]
struct Share {
    person_id: i64,
    weight: f64,
    owed: i64,
}

#[derive(Serialize)]
struct Bill {
    id: i64,
    description: String,
    currency: String,
    date: Option<String>,
    split_mode: String,
    total: i64,
    payers: Vec<Payer>,
    shares: Vec<Share>,
}

#[derive(Serialize)]
struct Balance {
    person_id: i64,
    paid: i64,
    owed: i64,
    net: i64,
}

#[derive(Serialize)]
struct TransferView {
    from: i64,
    to: i64,
    amount: i64,
    methods: Vec<String>,
}

#[derive(Serialize)]
struct Summary {
    balances: Vec<Balance>,
    transfers: Vec<TransferView>,
    unsettled: Vec<Balance>,
    /// Only populated when the payment graph is disconnected.
    components: Vec<Vec<i64>>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct StateView {
    name: String,
    base_currency: String,
    persons: Vec<Person>,
    groups: Vec<NamedSet>,
    methods: Vec<NamedSet>,
    rates: Vec<Rate>,
    bills: Vec<Bill>,
    summary: Summary,
}

fn load_sets(conn: &Connection, t: &SetTables, splitter_id: i64) -> rusqlite::Result<Vec<NamedSet>> {
    let mut sets: Vec<NamedSet> = conn
        .prepare(&format!(
            "SELECT id, name FROM {} WHERE splitter_id = ?1 ORDER BY name COLLATE NOCASE",
            t.table
        ))?
        .query_map([splitter_id], |r| Ok(NamedSet { id: r.get(0)?, name: r.get(1)?, member_ids: vec![] }))?
        .collect::<Result<_, _>>()?;
    let mut stmt = conn.prepare(&format!(
        "SELECT m.{fk}, m.person_id FROM {members} m JOIN {table} s ON s.id = m.{fk}
         WHERE s.splitter_id = ?1",
        fk = t.fk,
        members = t.members,
        table = t.table
    ))?;
    let rows = stmt.query_map([splitter_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
    for row in rows {
        let (sid, pid) = row?;
        if let Some(s) = sets.iter_mut().find(|s| s.id == sid) {
            s.member_ids.push(pid);
        }
    }
    Ok(sets)
}

async fn get_state(State(st): State<AppState>, auth: Auth) -> ApiResult<Json<StateView>> {
    let conn = st.db();
    let sid = auth.splitter_id;
    let (name, base_currency): (String, String) = conn.query_row(
        "SELECT name, base_currency FROM splitters WHERE id = ?1",
        [sid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let persons: Vec<Person> = conn
        .prepare("SELECT id, name FROM persons WHERE splitter_id = ?1 ORDER BY name COLLATE NOCASE")?
        .query_map([sid], |r| Ok(Person { id: r.get(0)?, name: r.get(1)? }))?
        .collect::<Result<_, _>>()?;
    let groups = load_sets(&conn, &GROUPS, sid)?;
    let methods = load_sets(&conn, &METHODS, sid)?;
    let rates: Vec<Rate> = conn
        .prepare("SELECT code, rate FROM rates WHERE splitter_id = ?1 ORDER BY code")?
        .query_map([sid], |r| Ok(Rate { code: r.get(0)?, rate: r.get(1)? }))?
        .collect::<Result<_, _>>()?;

    let mut bills: Vec<Bill> = conn
        .prepare(
            "SELECT id, description, currency, date, split_mode FROM bills
             WHERE splitter_id = ?1 ORDER BY date DESC, id DESC",
        )?
        .query_map([sid], |r| {
            Ok(Bill {
                id: r.get(0)?,
                description: r.get(1)?,
                currency: r.get(2)?,
                date: r.get(3)?,
                split_mode: r.get(4)?,
                total: 0,
                payers: vec![],
                shares: vec![],
            })
        })?
        .collect::<Result<_, _>>()?;
    let index: HashMap<i64, usize> = bills.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let mut stmt = conn.prepare(
        "SELECT p.bill_id, p.person_id, p.amount FROM bill_payers p
         JOIN bills b ON b.id = p.bill_id WHERE b.splitter_id = ?1",
    )?;
    for row in stmt.query_map([sid], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?)))? {
        let (bid, person_id, amount) = row?;
        let bill = &mut bills[index[&bid]];
        bill.total += amount;
        bill.payers.push(Payer { person_id, amount });
    }
    let mut stmt = conn.prepare(
        "SELECT s.bill_id, s.person_id, s.weight, s.owed FROM bill_shares s
         JOIN bills b ON b.id = s.bill_id WHERE b.splitter_id = ?1",
    )?;
    for row in stmt.query_map([sid], |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))? {
        let (bid, person_id, weight, owed) = row?;
        bills[index[&bid]].shares.push(Share { person_id, weight, owed });
    }

    let summary = summarize(&base_currency, &persons, &methods, &rates, &bills);
    Ok(Json(StateView { name, base_currency, persons, groups, methods, rates, bills, summary }))
}

fn summarize(base: &str, persons: &[Person], methods: &[NamedSet], rates: &[Rate], bills: &[Bill]) -> Summary {
    let mut warnings = Vec::new();
    let names: HashMap<i64, &str> = persons.iter().map(|p| (p.id, p.name.as_str())).collect();
    let mut rate_of: HashMap<&str, f64> = rates.iter().map(|r| (r.code.as_str(), r.rate)).collect();
    rate_of.insert(base, 1.0);

    // Balances in base-currency cents, as exact floats first.
    let ids: Vec<PersonId> = persons.iter().map(|p| p.id).collect();
    let mut paid: HashMap<i64, f64> = ids.iter().map(|&i| (i, 0.0)).collect();
    let mut owed: HashMap<i64, f64> = paid.clone();
    let mut missing = BTreeSet::new();
    for bill in bills {
        let Some(&r) = rate_of.get(bill.currency.as_str()) else {
            missing.insert(bill.currency.clone());
            continue;
        };
        for p in &bill.payers {
            *paid.entry(p.person_id).or_default() += p.amount as f64 * r;
        }
        for s in &bill.shares {
            *owed.entry(s.person_id).or_default() += s.owed as f64 * r;
        }
    }
    for code in &missing {
        warnings.push(format!(
            "No exchange rate for {code}: bills in {code} are left out of the balances until you add one."
        ));
    }
    let exact: Vec<f64> = ids.iter().map(|i| paid[i] - owed[i]).collect();
    let nets = settle::apportion(&exact, 0);
    let balances: Vec<Balance> = ids
        .iter()
        .zip(&nets)
        .map(|(&i, &net)| {
            let p = paid[&i].round() as i64;
            Balance { person_id: i, paid: p, owed: p - net, net }
        })
        .collect();

    // Payment graph: people can pay each other if they share a method.
    let mut pair_methods: HashMap<(i64, i64), Vec<String>> = HashMap::new();
    let adj: Adjacency = if methods.is_empty() {
        None
    } else {
        let mut m: HashMap<PersonId, BTreeSet<PersonId>> = ids.iter().map(|&i| (i, BTreeSet::new())).collect();
        for method in methods {
            for &a in &method.member_ids {
                for &b in &method.member_ids {
                    if a < b {
                        m.entry(a).or_default().insert(b);
                        m.entry(b).or_default().insert(a);
                        pair_methods.entry((a, b)).or_default().push(method.name.clone());
                    }
                }
            }
        }
        Some(m)
    };
    let comps = settle::components(&ids, &adj);
    let components = if comps.len() > 1 {
        let described: Vec<String> = comps
            .iter()
            .map(|c| c.iter().map(|i| names[i]).collect::<Vec<_>>().join(", "))
            .collect();
        warnings.push(format!(
            "Not everyone can pay everyone: the payment methods split people into {} separate groups ({}). \
             Add payment methods that connect them.",
            comps.len(),
            described.join(" | ")
        ));
        comps
    } else {
        vec![]
    };

    let bal_map: BTreeMap<PersonId, i64> = ids.iter().copied().zip(nets.iter().copied()).collect();
    let (transfers, left) = settle::settle(&bal_map, &adj);
    let transfers = transfers
        .into_iter()
        .map(|t| {
            let key = (t.from.min(t.to), t.from.max(t.to));
            TransferView {
                from: t.from,
                to: t.to,
                amount: t.amount,
                methods: pair_methods.get(&key).cloned().unwrap_or_default(),
            }
        })
        .collect();
    let unsettled = left
        .into_iter()
        .map(|(person_id, net)| Balance { person_id, paid: 0, owed: 0, net })
        .collect();

    Summary { balances, transfers, unsettled, components, warnings }
}
