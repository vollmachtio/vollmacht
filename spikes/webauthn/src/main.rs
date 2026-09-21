use vollmacht_webauthn_probe::{ORIGIN, ceremony::random_token, http::router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = random_token().map_err(|_| "OS randomness unavailable")?;
    let app = router(token.clone())?;
    // Bind before showing the token, and never fall back to a different origin.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8374").await?;
    println!(
        "Experimental passkey probe. No mandates or GitHub operations.\nOpen {ORIGIN}\nSession token (paste into the page; do not share):\n{token}\nCtrl-C stops the server. Test passkeys may remain in your password provider."
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
