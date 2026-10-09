mod api;
mod db;
mod settle;

use std::env;

#[tokio::main]
async fn main() {
    let db_path = env::var("SPLITTER_DB").unwrap_or_else(|_| "splitter.db".into());
    let addr = env::var("SPLITTER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());

    let conn = db::open(&db_path).unwrap_or_else(|e| panic!("cannot open database {db_path}: {e}"));
    let app = api::router(api::AppState::new(conn));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    println!("Splitter listening on http://{addr} (database: {db_path})");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
