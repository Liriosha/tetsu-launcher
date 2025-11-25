mod auth;
use auth::MicrosoftAuthSession;

fn main() {
    println!("THIS IS A TEST BUILD!");
    let client_id = "c36a9fb6-4f2a-41ff-90bd-ae7cc92031eb";
    let redirect_port = 28562;

    println!("Opening Microsoft login webview...");

    let code = match MicrosoftAuthSession::authenticate_with_webview("", client_id, redirect_port) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("❌ Failed to get authorization code: {}", err);
            return;
        }
    };

    println!("✅ Got authorization code: {}", code);

    println!("Exchanging code for Microsoft/Xbox/Minecraft tokens...");

    match MicrosoftAuthSession::authenticate(
        client_id,
        client_id,
        &code,
        &format!("http://127.0.0.1:{}", redirect_port),
    ) {
        Ok(sess) => {
            println!("\n✅ Authentication successful!");
            println!("Username: {}", sess.username);
            println!("UUID: {}", sess.uuid);
            println!("Access Token (truncated): {}...", &sess.access_token[..20.min(sess.access_token.len())]);
        }
        Err(err) => eprintln!("\n❌ Authentication failed: {}", err),
    }

    println!("Done.");
}
