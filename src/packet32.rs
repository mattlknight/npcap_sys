// MIT License
// Copyright (c) 2019 Matthew Knight
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// #include <winsock2.h>
// #include <airpcap.h>
// #include <dagc.h>
//! Npcap SDK Packet32.h Bindings
use winapi::ctypes;
use winapi::shared::{minwindef, ntdef, ws2def};
use winapi::um::{minwinbase, winsock2};
// FIXME: Import types from airpcap.rs
// FIXME: Import types from dagc.rs
// pub type _AirpcapHandle = *mut PAirpcapHandle;
pub const PACKET_MODE_CAPT: usize = 0x0; // Capture mode
pub const PACKET_MODE_STAT: usize = 0x1; // Statistical mode
pub const PACKET_MODE_MON: usize = 0x2; // Monitoring mode
pub const PACKET_MODE_DUMP: usize = 0x10; // Dump mode
pub const PACKET_MODE_STAT_DUMP: usize = PACKET_MODE_DUMP | PACKET_MODE_STAT; // Statistical dump mode
// FIXME: Constant Function sizeof(int)
// #define Packet_ALIGNMENT sizeof(int)
// FIXME: Constant Function, depends on Packet_ALIGNMENT
// #define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))
pub const NdisMediumNull: isize = -1;
pub const NdisMediumCHDLC: isize = -2;
pub const NdisMediumPPPSerial: isize = -3;
pub const NdisMediumBare80211: isize = -4;
pub const NdisMediumRadio80211: isize = -5;
pub const NdisMediumPpi: isize = -6;
pub const NPF_DISABLE_LOOPBACK: usize = 1;
pub const NPF_ENABLE_LOOPBACK: usize = 2;
STRUCT!{struct NetType {
    LinkType: minwindef::UINT,
    LinkSpeed: ntdef::ULONGLONG,
}}
STRUCT!{struct bpf_program {
    bf_len: minwindef::UINT,
    bf_insns: *mut bpf_insn,
}}
STRUCT!{struct bpf_insn {
    code: minwindef::USHORT,
    jt: minwindef::UCHAR,
    jf: minwindef::UCHAR,
    k: ctypes::c_int,
}}
STRUCT!{struct bpf_stat {
    bs_recv: minwindef::UINT,
    bs_drop: minwindef::UINT,
    ps_ifdrop: minwindef::UINT,
    bs_capt: minwindef::UINT,
}}
pub type timeval = winsock2::timeval;
STRUCT!{struct bpf_hdr {
    bh_tstamp: timeval,
    bh_caplen: minwindef::UINT,
    bh_datalen: minwindef::UINT,
    bh_hdrlen: minwindef::USHORT,
}}
STRUCT!{struct dump_bpf_hdr {
    ts: timeval,
    caplen: minwindef::UINT,
    len: minwindef::UINT,
}}
pub const DOSNAMEPREFIX: &'static str = "Packet_";
pub const MAX_LINK_NAME_LENGTH: usize = 64;
pub const NMAX_PACKET: usize = 65535;
pub type sockaddr_storage = ws2def::SOCKADDR_STORAGE;
STRUCT!{struct npf_if_addr {
    IPAddress: sockaddr_storage,
    SubnetMask: sockaddr_storage,
    Broadcast: sockaddr_storage,
}}
pub const ADAPTER_NAME_LENGTH: usize = 256 + 12;
pub const ADAPTER_DESC_LENGTH: usize = 128;
pub const MAX_MAC_ADDR_LENGTH: usize = 8;
pub const MAX_NETWORK_ADDRESSES: usize = 16;
STRUCT!{struct WAN_ADAPTER_INT {
    _private: [u8; 0], // typedef struct WAN_ADAPTER_INT WAN_ADAPTER; // has no fields
}}
pub type WAN_ADAPTER = WAN_ADAPTER_INT;
pub type PWAN_ADAPTER = *mut WAN_ADAPTER;
pub const INFO_FLAG_NDIS_ADAPTER: usize = 0;
pub const INFO_FLAG_NDISWAN_ADAPTER: usize = 1;
pub const INFO_FLAG_DAG_CARD: usize = 2;
pub const INFO_FLAG_DAG_FILE: usize = 6;
pub const INFO_FLAG_DONT_EXPORT: usize = 8;
pub const INFO_FLAG_AIRPCAP_CARD: usize = 16;
pub const INFO_FLAG_NPFIM_DEVICE: usize = 32;
STRUCT!{struct _ADAPTER {
    hFile: ntdef::HANDLE,
    SymbolicLink: ntdef::CHAR, // CHAR SymbolicLink[MAX_LINK_NAME_LENGTH]; // FIXME: Unsure how to handle this
    NumWrites: ctypes::c_int,
    ReadEvent: ntdef::HANDLE,
    ReadTimeOut: minwindef::UINT,
    Name: ntdef::CHAR, // CHAR Name[ADAPTER_NAME_LENGTH]; // FIXME: Unsure how to handle this
    pWanAdapter: PWAN_ADAPTER,
    Flags: minwindef::UINT,
    // AirpcapAd: PAirpcapHandle, // FIXME: Import types from airpcap.rs
    // void* NpfImHandle, // FIXME: Unsure how to handle this
    // pDagCard: *mut dagc_t, // FIXME: Import types from dagc.rs
    DagBuffer: ntdef::PCHAR,
    DagReadTimeout: timeval,
    DagFcsLen: ctypes::c_uint, // unsigned DagFcsLen; // FIXME: Not sure if correct rust type
    DagFastProcess: minwindef::DWORD,
}}
pub type ADAPTER = _ADAPTER;
pub type LPADAPTER = *mut _ADAPTER;
STRUCT!{struct _PACKET {
    hEvent: ntdef::HANDLE,
    OverLapped: minwinbase::OVERLAPPED,
    Buffer: ntdef::PVOID,
    Length: minwindef::UINT,
    ulBytesReceived: minwindef::DWORD,
    bIoComplete: ntdef::BOOLEAN,
}}
pub type PACKET = _PACKET;
pub type LPPACKET = *mut _PACKET;
STRUCT!{struct _PACKET_OID_DATA {
    Oid: minwindef::ULONG,
    Length: minwindef::ULONG,
    Data: minwindef::UCHAR, // UCHAR Data[1]; // FIXME: Unsure if correct
}}
// FIXME: Unsure if correct rust translation
// typedef struct _PACKET_OID_DATA PACKET_OID_DATA, * PPACKET_OID_DATA;
pub type PACKET_OID_DATA = *mut _PACKET_OID_DATA;
pub type PPACKET_OID_DATA = *mut _PACKET_OID_DATA;
extern "C" {
    pub fn PacketGetVersion() -> ntdef::PCHAR;
    pub fn PacketGetDriverVersion() -> ntdef::PCHAR;
    pub fn PacketGetDriverName() -> ntdef::PCHAR;
    pub fn PacketSetMinToCopy(
        AdapterObject: LPADAPTER,
        nbytes: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetNumWrites(
        AdapterObject: LPADAPTER,
        nwrites: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetMode(
        AdapterObject: LPADAPTER,
        mode: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetReadTimeout(
        AdapterObject: LPADAPTER,
        timeout: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetBpf(
        AdapterObject: LPADAPTER,
        fp: *mut bpf_program,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetLoopbackBehavior(
        AdapterObject: LPADAPTER,
        LoopbackBehavior: minwindef::UINT,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetSnapLen(
        AdapterObject: LPADAPTER,
        snaplen: ctypes::c_int,
    ) -> ntdef::INT;
    pub fn PacketGetStats(
        AdapterObject: LPADAPTER,
        s: *mut bpf_stat,
    ) -> ntdef::BOOLEAN;
    pub fn PacketGetStatsEx(
        AdapterObject: LPADAPTER,
        s: *mut bpf_stat,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetBuff(
        AdapterObject: LPADAPTER,
        dim: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketGetNetType(
        AdapterObject: LPADAPTER,
        type_: *mut NetType, // type
    ) -> ntdef::BOOLEAN;
    pub fn PacketIsLoopbackAdapter(
        AdapterName: ntdef::PCHAR,
    ) -> ntdef::BOOLEAN;
    pub fn PacketIsMonitorModeSupported(
        AdapterName: ntdef::PCHAR,
    ) -> ctypes::c_int;
    pub fn PacketSetMonitorMode(
        AdapterName: ntdef::PCHAR,
        mode: ctypes::c_int,
    ) -> ctypes::c_int;
    pub fn PacketGetMonitorMode(
        AdapterName: ntdef::PCHAR,
    ) -> ctypes::c_int;
    pub fn PacketOpenAdapter(
        AdapterName: ntdef::PCHAR,
    ) -> LPADAPTER;
    pub fn PacketSendPacket(
        AdapterObject: LPADAPTER,
        pPacket: LPPACKET,
        Sync_: ntdef::BOOLEAN, // Sync
    ) -> ntdef::BOOLEAN;
    pub fn PacketSendPackets(
        AdapterObject: LPADAPTER,
        PacketBuff: ntdef::PVOID,
        Size: minwindef::ULONG,
        Sync_: ntdef::BOOLEAN, // Sync
    ) -> ctypes::c_int;
    pub fn PacketAllocatePacket(
        void: ctypes::c_void, // LPPACKET PacketAllocatePacket(void); // FIXME: Unsure if properly translated
    ) -> LPPACKET;
    pub fn PacketInitPacket(
        lpPacket: LPPACKET,
        Buffer: ntdef::PVOID,
        Length: minwindef::UINT,
    ) -> ntdef::VOID;
    pub fn PacketFreePacket(
        lpPacket: LPPACKET,
    ) -> ntdef::VOID;
    pub fn PacketReceivePacket(
        AdapterObject: LPADAPTER,
        lpPacket: LPPACKET,
        Sync_: ntdef::BOOLEAN, // Sync
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetHwFilter(
        AdapterObject: LPADAPTER,
        Filter: minwindef::ULONG,
    ) -> ntdef::BOOLEAN;
    pub fn PacketGetAdapterNames(
        pStr: ntdef::PCHAR,
        BufferSize: minwindef::PULONG,
    ) -> ntdef::BOOLEAN;
    pub fn PacketGetNetInfoEx(
        AdapterName: ntdef::PCHAR,
        buffer: *mut npf_if_addr,
        NEntries: minwindef::PULONG,
    ) -> ntdef::BOOLEAN;
    pub fn PacketRequest(
        AdapterObject: LPADAPTER,
        Set: ntdef::BOOLEAN,
        OidData: PPACKET_OID_DATA,
    ) -> ntdef::BOOLEAN;
    pub fn PacketGetReadEvent(
        AdapterObject: LPADAPTER,
    ) -> ntdef::HANDLE;
    pub fn PacketSetDumpName(
        AdapterObject: LPADAPTER,
        name: *mut ctypes::c_void,
        len: ctypes::c_int,
    ) -> ntdef::BOOLEAN;
    pub fn PacketSetDumpLimits(
        AdapterObject: LPADAPTER,
        maxfilesize: minwindef::UINT,
        maxnpacks: minwindef::UINT,
    ) -> ntdef::BOOLEAN;
    pub fn PacketIsDumpEnded(
        AdapterObject: LPADAPTER,
        Sync_: ntdef::BOOLEAN, // Sync
    ) -> ntdef::BOOLEAN;
    pub fn PacketStopDriver() -> minwindef::BOOL;
    pub fn PacketStopDriver60() -> minwindef::BOOL;
    pub fn PacketCloseAdapter(
        AdapterObject: LPADAPTER,
    ) -> ntdef::VOID;
    pub fn PacketStartOem(
        errorString: ntdef::PCHAR,
        errorStringLength: minwindef::UINT,
    ) -> ntdef::BOOLEAN;
    pub fn PacketStartOemEx(
        errorString: ntdef::PCHAR,
        errorStringLength: minwindef::UINT,
        flags: minwindef::ULONG,
    ) -> ntdef::BOOLEAN;
    // FIXME: Import types from airpcap.rs
    // pub fn PacketGetAirPcapHandle(
    //     AdapterObject: LPADAPTER,
    // ) -> PAirpcapHandle;
}
pub const PACKET_START_OEM_NO_NETMON: usize = 0x00000001;
