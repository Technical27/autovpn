use super::{Config, Msg};

use anyhow::{Context, Result};

use dbus::nonblock::{Proxy, SyncConnection};
use dbus_tokio::connection;

use log::*;

use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;

use std::sync::Arc;
use std::time::Duration;

fn get_network_proxy(conn: &SyncConnection) -> Proxy<'static, &SyncConnection> {
    Proxy::new(
        "org.freedesktop.network1",
        "/org/freedesktop/network1",
        Duration::from_secs(2),
        conn,
    )
}

async fn get_ifindex<'a>(proxy: &Proxy<'a, &SyncConnection>, ifname: &str) -> Result<i32> {
    let (ifindex,) = proxy
        .method_call(
            "org.freedesktop.network1.Manager",
            "GetLinkByName",
            (ifname,),
        )
        .await
        .context("failed to get link ifindex")?;

    Ok(ifindex)
}

async fn set_domains<'a>(
    proxy: &Proxy<'a, &SyncConnection>,
    ifindex: i32,
    domains: &[&str],
) -> Result<()> {
    let domains = domains.iter().map(|s| (*s, true)).collect::<Vec<_>>();
    Ok(proxy
        .method_call(
            "org.freedesktop.network1.Manager",
            "SetLinkDomains",
            (ifindex, domains),
        )
        .await
        .context("failed to set link domains")?)
}

async fn enable_dns(conn: &SyncConnection, ifname: &str) -> Result<()> {
    let proxy = get_network_proxy(conn);
    let ifindex = get_ifindex(&proxy, ifname).await?;
    set_domains(&proxy, ifindex, &[""]).await?;
    debug!("changed dns domain to ~.");
    Ok(())
}

async fn disable_dns(conn: &SyncConnection, ifname: &str) -> Result<()> {
    let proxy = get_network_proxy(conn);
    let ifindex = get_ifindex(&proxy, ifname).await?;
    set_domains(&proxy, ifindex, &[]).await?;
    debug!("removed dns domains");
    Ok(())
}

pub fn setup(mut rx: Receiver<Msg>, config: Arc<Config>) -> Result<JoinHandle<()>> {
    let (resource, conn) = connection::new_system_sync()?;
    debug!("got dbus connection");

    let err_handle = tokio::spawn(async {
        let err = resource.await;
        error!("lost system dbus connection: {}", err);
    });

    let handle = tokio::spawn(async move {
        while let Ok(m) = rx.recv().await {
            match m {
                Msg::Enable => {
                    if let Err(e) = enable_dns(&conn, &config.wireguard_interface).await {
                        error!("error on dns enable: {}", e);
                    }
                }
                Msg::Disable => {
                    if let Err(e) = disable_dns(&conn, &config.wireguard_interface).await {
                        error!("error on dns disable: {}", e);
                    }
                }
                Msg::Quit => {
                    err_handle.abort();
                    break;
                }
            }
        }
    });

    Ok(handle)
}
