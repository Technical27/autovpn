use anyhow::Result;

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags, Nlmsg},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::tokio::NlSocket,
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer, NlBuffer},
};

use tokio::sync::broadcast::Sender;
use tokio::task::JoinHandle;

use log::*;

use std::ffi::CStr;
use std::sync::Arc;

use super::{Config, Msg};
use neli_wifi::{Nl80211Attr, Nl80211Cmd, NL_80211_GENL_NAME};

fn parse_ifindex(bytes: &[u8]) -> u32 {
    let mut num: [u8; 4] = Default::default();
    num.copy_from_slice(bytes);
    u32::from_ne_bytes(num)
}

fn gen_nl80211_header(
    cmd: Nl80211Cmd,
    attrs: GenlBuffer<Nl80211Attr, Buffer>,
    id: u16,
    flags: &[NlmF],
) -> Nlmsghdr<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> {
    let genlhdr = Genlmsghdr::new(cmd, 1, attrs);
    Nlmsghdr::new(
        None,
        id,
        NlmFFlags::new(flags),
        None,
        None,
        NlPayload::Payload(genlhdr),
    )
}

async fn get_ssid(socket: &mut NlSocket, family: u16, ifindex: u32) -> Result<()> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        // nothing is nested
        false,
        // use native endian rather than network order
        false,
        Nl80211Attr::AttrIfindex,
        Buffer::from(ifindex.to_ne_bytes().as_ref()),
    )?);

    let nlhdr = gen_nl80211_header(Nl80211Cmd::CmdGetInterface, attrs, family, &[NlmF::Request]);
    socket.send(&nlhdr).await?;

    Ok(())
}

fn get_ifindex(socket: &mut NlSocketHandle, family: u16, ifname: &str) -> Result<Option<u32>> {
    let attrs = GenlBuffer::new();
    let nlhdr = gen_nl80211_header(
        Nl80211Cmd::CmdGetInterface,
        attrs,
        family,
        &[NlmF::Request, NlmF::Dump],
    );
    socket.send(nlhdr)?;

    let mut check_done = false;
    let msgs: NlBuffer<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> = socket.recv_all()?;
    let mut ifindex = None;

    for msg in msgs {
        if msg.nl_flags.contains(&NlmF::Multi) {
            check_done = true;
        }

        if let Some(payload) = msg.nl_payload.get_payload() {
            let attrs = payload.get_attr_handle();
            if let Some(attr) = attrs.get_attribute(Nl80211Attr::AttrIfname) {
                let i = CStr::from_bytes_with_nul(attr.nla_payload.as_ref())?.to_string_lossy();

                if i == ifname {
                    ifindex = attrs
                        .get_attribute(Nl80211Attr::AttrIfindex)
                        .map(|attr| parse_ifindex(attr.nla_payload.as_ref()));
                }
            }
        }
    }

    if check_done {
        if let Some(done) = socket.recv::<Nlmsg, Buffer>()? {
            if done.nl_type != Nlmsg::Done {
                return Err(anyhow::anyhow!("no done message recieved"));
            }
        }
    }

    if let Some(i) = ifindex {
        debug!("got ifindex for {}: {}", ifname, i);
    } else {
        debug!("failed to find ifindex to check current network, will get later");
    }

    Ok(ifindex)
}

async fn cmd_connect(
    socket: &mut NlSocket,
    ifindex: &mut Option<u32>,
    family: u16,
    header: &Genlmsghdr<Nl80211Cmd, Nl80211Attr>,
) {
    debug!("interface connect to new network, trying to get ssid");
    let attrs = header.get_attr_handle();

    if let Some(attr) = attrs.get_attribute(Nl80211Attr::AttrIfindex) {
        let current_ifindex = parse_ifindex(attr.nla_payload.as_ref());
        let ifindex = *ifindex.get_or_insert(current_ifindex);

        if ifindex != current_ifindex {
            debug!("other interface connect, ignoring");
            return;
        }

        if let Err(e) = get_ssid(socket, family, ifindex).await {
            error!("failed to get ssid: {}", e);
        }
    } else {
        warn!("no ifindex for new connection, ignoring");
    }
}

async fn cmd_new_interface(
    header: &Genlmsghdr<Nl80211Cmd, Nl80211Attr>,
    tx: &Sender<Msg>,
    known_networks: &Vec<String>,
) {
    let attrs = header.get_attr_handle();
    debug!("attempting to get ssid from message");
    if let Some(attr) = attrs.get_attribute(Nl80211Attr::AttrSsid) {
        let ssid = String::from_utf8_lossy(attr.nla_payload.as_ref());
        if known_networks.iter().any(|s| *s == ssid) {
            info!("connected to known network '{}', disabling", ssid);
            tx.send(Msg::Disable).unwrap();
        } else {
            info!("connected to unknown network '{}', enabling", ssid);
            tx.send(Msg::Enable).unwrap();
        }
    } else {
        debug!("no ssid when there should be one, ignoring");
    }
}

async fn handle_payload(
    socket: &mut NlSocket,
    ifindex: &mut Option<u32>,
    family: u16,
    tx: &Sender<Msg>,
    payload: &Genlmsghdr<Nl80211Cmd, Nl80211Attr>,
    known_networks: &Vec<String>,
) {
    match payload.cmd {
        Nl80211Cmd::CmdConnect => {
            cmd_connect(socket, ifindex, family, payload).await;
        }

        Nl80211Cmd::CmdDisconnect => {
            debug!("interface disconnect from network");
            tx.send(Msg::Disable).unwrap();
        }

        Nl80211Cmd::CmdNewInterface => {
            cmd_new_interface(payload, &tx, known_networks).await;
        }
        _ => {}
    }
}

async fn handle_messages(
    socket: &mut NlSocket,
    ifindex: &mut Option<u32>,
    family: u16,
    tx: &Sender<Msg>,
    messages: NlBuffer<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>,
    known_networks: &Vec<String>,
) {
    for msg in messages {
        if msg.nl_flags.contains(&NlmF::Request) {
            continue;
        }

        if let Some(payload) = msg.nl_payload.get_payload() {
            handle_payload(socket, ifindex, family, tx, payload, known_networks).await;
        }
    }
}

async fn recieve_messages(
    socket: &mut NlSocket,
    ifindex: &mut Option<u32>,
    family: u16,
    tx: &Sender<Msg>,
    known_networks: &Vec<String>,
) {
    let mut buffer = Vec::new();

    while let Ok(msgs) = socket
        .recv::<u16, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buffer)
        .await
    {
        handle_messages(socket, ifindex, family, tx, msgs, known_networks).await;
    }
}

pub fn setup(tx: Sender<Msg>, config: Arc<Config>) -> Result<JoinHandle<()>> {
    let mut handle = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    let family = handle.resolve_genl_family(NL_80211_GENL_NAME)?;
    let id = handle.resolve_nl_mcast_group(NL_80211_GENL_NAME, "mlme")?;
    handle.add_mcast_membership(&[id])?;
    let mut ifindex = get_ifindex(&mut handle, family, &config.wlan_interface)?;

    let mut socket = NlSocket::new(handle)?;

    debug!("got nl80211 multicast notifications");

    let handle = tokio::spawn(async move {
        if let Some(i) = ifindex {
            debug!("attempt to get current ssid");

            if let Err(e) = get_ssid(&mut socket, family, i).await {
                error!("failed to get ssid: {}", e);
            }

            recieve_messages(
                &mut socket,
                &mut ifindex,
                family,
                &tx,
                &config.known_networks,
            )
            .await;
        }
    });

    Ok(handle)
}
