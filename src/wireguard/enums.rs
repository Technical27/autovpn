use neli::consts::genl::{Cmd, NlAttrType};
use neli_proc_macros::neli_enum;

#[neli_enum(serialized_type = "u8")]
pub enum WgCmd {
    CmdGetDevice = 0,
    CmdSetDevice = 1,
}

impl Cmd for WgCmd {}

#[neli_enum(serialized_type = "u16")]
pub enum WgDeviceAttr {
    AttrUnspec = 0,
    AttrIfindex = 1,
    AttrIfname = 2,
    AttrPrivateKey = 3,
    AttrPublicKey = 4,
    AttrFlags = 5,
    AttrListenPort = 6,
    AttrFwmark = 7,
    AttrPeers = 8,
}

impl NlAttrType for WgDeviceAttr {}
