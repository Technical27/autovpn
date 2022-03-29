use super::Msg;
use anyhow::{Context, Result};
use dbus::nonblock::{Proxy, SyncConnection};
use dbus_tokio::connection;
use log::*;
use std::time::Duration;
use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;

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

async fn enable_dns(conn: &SyncConnection) -> Result<()> {
    let proxy = get_network_proxy(&conn);
    let ifindex = get_ifindex(&proxy, "wg0").await?;
    set_domains(&proxy, ifindex, &[""]).await?;
    Ok(())
}

async fn disable_dns(conn: &SyncConnection) -> Result<()> {
    let proxy = get_network_proxy(&conn);
    let ifindex = get_ifindex(&proxy, "wg0").await?;
    set_domains(&proxy, ifindex, &[]).await?;
    Ok(())
}

pub fn setup(mut rx: Receiver<Msg>) -> Result<JoinHandle<()>> {
    let (resource, conn) = connection::new_system_sync()?;

    let err_handle = tokio::spawn(async {
        let err = resource.await;
        panic!("lost system dbus connection: {}", err);
    });

    let handle = tokio::spawn(async move {
        loop {
            let res = rx.recv().await;
            if let Ok(m) = res {
                match m {
                    Msg::Enable => {
                        if let Err(e) = enable_dns(&conn).await {
                            error!("error on dns enable: {}", e);
                        }
                    }
                    Msg::Disable => {
                        if let Err(e) = disable_dns(&conn).await {
                            error!("error on dns disable: {}", e);
                        }
                    }
                    Msg::Quit => {
                        err_handle.abort();
                        break;
                    }
                }
            }
        }
    });

    Ok(handle)
}
