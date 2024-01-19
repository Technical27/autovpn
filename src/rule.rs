use anyhow::{Context, Result};

use neli::{
    consts::{
        nl::{NlmF, NlmFFlags, Nlmsg},
        rtnl::{RtAddrFamily, Rta, Rtm},
        socket::NlFamily,
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Rtattr, Rtmsg},
    socket::NlSocketHandle,
    types::{Buffer, NlBuffer, RtBuffer},
};
use tokio::sync::broadcast::Receiver;
use tokio::task::JoinHandle;

use std::sync::Arc;

use log::*;

use super::{Config, Msg};

fn generate_rtattrs(fwmark: u32, table: u32) -> RtBuffer<Rta, Buffer> {
    let mut buf = RtBuffer::new();
    buf.push(Rtattr {
        rta_len: 5,
        rta_type: Rta::Src,
        rta_payload: Buffer::from(vec![0]),
    });
    buf.push(Rtattr {
        rta_len: 8,
        rta_type: Rta::Mark,
        rta_payload: Buffer::from(fwmark.to_ne_bytes().to_vec()),
    });
    buf.push(Rtattr {
        rta_len: 8,
        rta_type: Rta::Table,
        rta_payload: Buffer::from(table.to_ne_bytes().to_vec()),
    });

    buf
}

fn generate_rule_msg(family: RtAddrFamily, fwmark: u32, table: u32) -> Rtmsg {
    use neli::consts::rtnl::*;

    Rtmsg {
        rtm_family: family,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Default,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unicast,
        rtm_flags: RtmFFlags::new(&[]),
        rtattrs: generate_rtattrs(fwmark, table),
    }
}

fn generate_msg_header(
    family: RtAddrFamily,
    rtm: Rtm,
    fwmark: u32,
    table: u32,
    flags: &[NlmF],
) -> Nlmsghdr<Rtm, Rtmsg> {
    let msg = generate_rule_msg(family, fwmark, table);
    Nlmsghdr::new(
        None,
        rtm,
        NlmFFlags::new(flags),
        None,
        None,
        NlPayload::Payload(msg),
    )
}

fn add_rule(
    socket: &mut NlSocketHandle,
    family: RtAddrFamily,
    fwmark: u32,
    table: u32,
) -> Result<()> {
    if !check_rules(socket, family, fwmark, table).context("failed to check rules")? {
        trace!("adding rule for family: {:?}", family);
        socket.send(generate_msg_header(
            family,
            Rtm::Newrule,
            fwmark,
            table,
            &[NlmF::Request, NlmF::Create, NlmF::Excl],
        ))?;
    }

    Ok(())
}

fn check_rule(msg: &Rtmsg) -> bool {
    for attr in msg.rtattrs.iter() {
        if attr.rta_type == Rta::Table {
            let mut num: [u8; 4] = Default::default();
            num.copy_from_slice(attr.rta_payload.as_ref());

            if u32::from_ne_bytes(num) == 1000 {
                return true;
            }
        }
    }

    false
}

fn check_rules(
    socket: &mut NlSocketHandle,
    family: RtAddrFamily,
    fwmark: u32,
    table: u32,
) -> Result<bool> {
    let header = generate_msg_header(
        family,
        Rtm::Getrule,
        fwmark,
        table,
        &[NlmF::Request, NlmF::Match],
    );

    debug!("sending messages");
    socket.send(header)?;
    debug!("sent messages");

    let mut rule_exists = false;
    let mut check_done = false;
    let msgs: NlBuffer<Rtm, Rtmsg> = socket.recv_all()?;
    for msg in msgs {
        if msg.nl_flags.contains(&NlmF::Multi) {
            check_done = true;
        }

        if let Some(payload) = msg.nl_payload.get_payload() {
            if check_rule(payload) {
                rule_exists = true;
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

    debug!("done iterating messages");
    Ok(rule_exists)
}

fn remove_rule(
    socket: &mut NlSocketHandle,
    family: RtAddrFamily,
    fwmark: u32,
    table: u32,
) -> Result<()> {
    if check_rules(socket, family, fwmark, table).context("failed to check rules")? {
        trace!("removing rule for family: {:?}", family);
        socket
            .send(generate_msg_header(
                family,
                Rtm::Delrule,
                fwmark,
                table,
                &[NlmF::Request],
            ))
            .context("failed to send msg")?;
    }
    Ok(())
}

async fn enable_rules(config: Arc<Config>) -> Result<()> {
    let config = config.clone();

    let fwmark = config.firewall_mark;
    let table = config.routing_table;
    let ipv6 = config.ipv6;

    tokio::task::spawn_blocking(move || {
        let mut socket = create_handle();
        add_rule(&mut socket, RtAddrFamily::Inet, fwmark, table)?;
        debug!("enabled ipv4 rules");

        if ipv6 {
            add_rule(&mut socket, RtAddrFamily::Inet6, fwmark, table)?;
            debug!("enabled ipv6 rules");
        }

        Ok(())
    })
    .await?
}

async fn disable_rules(config: Arc<Config>) -> Result<()> {
    let config = config.clone();

    let fwmark = config.firewall_mark;
    let table = config.routing_table;

    tokio::task::spawn_blocking(move || {
        let mut socket = create_handle();
        remove_rule(&mut socket, RtAddrFamily::Inet, fwmark, table)?;
        debug!("disabled ipv4 rules");

        // Always disable ipv6 rules, because they may persist between config changes
        remove_rule(&mut socket, RtAddrFamily::Inet6, fwmark, table)?;
        debug!("disabled ipv6 rules");

        Ok(())
    })
    .await?
}

fn create_handle() -> NlSocketHandle {
    NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap()
}

pub fn setup(mut rx: Receiver<Msg>, config: Arc<Config>) -> JoinHandle<()> {
    let config = config.clone();
    tokio::spawn(async move {
        while let Ok(m) = rx.recv().await {
            match m {
                Msg::Enable => {
                    if let Err(e) = enable_rules(config.clone()).await {
                        error!("error on rule enable: {}", e);
                    }
                }
                Msg::Disable => {
                    if let Err(e) = disable_rules(config.clone()).await {
                        error!("error on rule enable: {}", e);
                    }
                }
                Msg::Quit => break,
            }
        }
    })
}
