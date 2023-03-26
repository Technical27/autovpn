mod networkd;
mod rule;
mod wifi;
mod wireguard;

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast::channel;
use tokio::time::{sleep, Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    let r_handle = rule::setup(rx);
    let w_handle = wifi::setup(tx.clone())?;
    let wg_handle = wireguard::setup(tx.subscribe());

    let done = Arc::new(AtomicBool::new(true));

    let d = done.clone();
    ctrlc::set_handler(move || {
        d.store(false, Ordering::SeqCst);
    })
    .context("failed to set ctrlc handler")?;

    while done.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
    }

    w_handle.abort();
    wg_handle.abort();
    tx.send(Msg::Disable)?;
    tx.send(Msg::Quit)?;
    n_handle.await?;
    r_handle.await?;
    Ok(())
}
