use anyhow::Result;

use neli::{
    consts::{
        nl::{GenlId, NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    socket::tokio::NlSocket,
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};

use tokio::sync::broadcast::Sender;
use tokio::task::JoinHandle;

use log::*;

use super::nl80211::*;
use super::Msg;

fn parse_ifindex(bytes: &[u8]) -> u32 {
    let mut num: [u8; 4] = Default::default();
    num.copy_from_slice(bytes);
    u32::from_ne_bytes(num)
}

fn gen_nl80211_header(
    cmd: Nl80211Cmd,
    attrs: GenlBuffer<Nl80211Attr, Buffer>,
    id: GenlId,
    flags: &[NlmF],
) -> Nlmsghdr<GenlId, Genlmsghdr<Nl80211Cmd, Nl80211Attr>> {
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

pub async fn get_ssid(socket: &mut NlSocket, nlid: u16, ifindex: u32) -> Result<()> {
    let mut attrs = GenlBuffer::new();
    attrs.push(Nlattr::new(
        false,
        false,
        Nl80211Attr::Ifindex.into(),
        Buffer::from(ifindex.to_ne_bytes().as_ref()),
    )?);

    let nlhdr = gen_nl80211_header(
        Nl80211Cmd::GetInterface,
        attrs,
        GenlId::UnrecognizedConst(nlid),
        &[NlmF::Request],
    );
    socket.send(&nlhdr).await?;

    Ok(())
}

pub fn setup(tx: Sender<Msg>) -> Result<JoinHandle<()>> {
    let mut handle = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    let family = handle.resolve_genl_family("nl80211")?;
    let id = handle.resolve_nl_mcast_group("nl80211", "mlme")?;
    handle.add_mcast_membership(&[id])?;
    let mut socket = NlSocket::new(handle)?;
    let mut buffer = Vec::new();

    let mut ifindex = None;

    let handle = tokio::spawn(async move {
        while let Ok(msgs) = socket
            .recv::<GenlId, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buffer)
            .await
        {
            for msg in msgs {
                if let Some(payload) = msg.nl_payload.get_payload() {
                    let attrs = payload.get_attr_handle();

                    match payload.cmd {
                        Nl80211Cmd::Connect => {
                            if ifindex.is_none() {
                                if let Some(attr) = attrs.get_attribute(Nl80211Attr::Ifindex) {
                                    ifindex = Some(parse_ifindex(attr.nla_payload.as_ref()));
                                }
                            }

                            if let Err(e) = get_ssid(&mut socket, family, ifindex.unwrap()).await {
                                error!("failed to get ssid: {}", e);
                            }
                        }

                        Nl80211Cmd::Disconnect => {
                            debug!("disconnect");
                            tx.send(Msg::Disable).unwrap();
                        }

                        Nl80211Cmd::NewInterface => {
                            if let Some(attr) = attrs.get_attribute(Nl80211Attr::Ssid) {
                                let ssid = String::from_utf8_lossy(attr.nla_payload.as_ref());
                                if ssid == "JAY2" {
                                    debug!("disconnect");
                                    tx.send(Msg::Disable).unwrap();
                                } else {
                                    debug!("connect");
                                    tx.send(Msg::Enable).unwrap();
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(handle)
}
