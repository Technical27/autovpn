mod networkd;
mod nl80211;
mod rule;
mod wifi;

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast::channel;

#[derive(Clone, Copy, Debug)]
pub enum Msg {
    Enable,
    Disable,
    Quit,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let (tx, rx) = channel::<Msg>(32);

    let n_handle = networkd::setup(tx.subscribe())?;
    let r_handle = rule::setup(rx)?;
    let w_handle = wifi::setup(tx.clone())?;

    let done = Arc::new(AtomicBool::new(true));

    let d = done.clone();
    ctrlc::set_handler(move || {
        d.store(false, Ordering::SeqCst);
    })
    .context("failed to set ctrlc handler")?;

    while done.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }

    w_handle.abort();
    tx.send(Msg::Disable)?;
    tx.send(Msg::Quit)?;
    n_handle.await?;
    r_handle.await?;
    Ok(())
}
