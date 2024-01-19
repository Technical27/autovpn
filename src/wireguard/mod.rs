use super::{Config, Msg};

use anyhow::Result;

use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};

use std::ffi::CString;
use std::sync::Arc;

use log::*;

mod enums;

use enums::{WgCmd, WgDeviceAttr};

async fn change_listen_port(ifname: &str) -> Result<()> {
    let ifname = CString::new(ifname)?;

    tokio::task::spawn_blocking(move || {
        let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;
        let family = socket.resolve_genl_family("wireguard")?;

        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(
            // nothing is nested
            false,
            // use native endian rather than network order
            false,
            WgDeviceAttr::AttrListenPort,
            Buffer::from(0u16.to_ne_bytes().as_ref()),
        )?);
        attrs.push(Nlattr::new(
            // nothing is nested
            false,
            // use native endian rather than network order
            false,
            WgDeviceAttr::AttrIfname,
            Buffer::from(ifname.to_bytes_with_nul()),
        )?);

        let genlheader = Genlmsghdr::new(WgCmd::CmdSetDevice, 1, attrs);
        let header = Nlmsghdr::new(
            None,
            family,
            NlmFFlags::new(&[NlmF::Request]),
            None,
            None,
            NlPayload::Payload(genlheader),
        );

        socket.send(header)?;

        debug!("changed wireguard listen port");

        Ok(())
    })
    .await?
}

pub fn setup(mut rx: Receiver<Msg>, config: Arc<Config>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if msg == Msg::Enable {
                // Some networks have odd NAT and firewalls which means that the last used port is
                // likely not usable. Change the port once to improve the odds.
                if let Err(e) = change_listen_port(&config.wireguard_interface).await {
                    error!("failed to change wireguard listen port: {}", e);
                }
            }
        }
    })
}
