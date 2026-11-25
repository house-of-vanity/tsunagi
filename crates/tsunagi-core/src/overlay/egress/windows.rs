//! Winsock takes the IPv4 interface index in network byte order.
#![allow(unsafe_code)]
use std::{io, os::windows::io::AsRawSocket};
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, WSAGetLastError, setsockopt,
};

pub(super) fn pin(socket: &impl AsRawSocket, index: u32) -> io::Result<()> {
    #[cfg(test)]
    if index == 0 {
        return Ok(());
    }
    if index == 0 {
        return Err(io::Error::other("no physical exit interface"));
    }
    let bytes = index.to_be_bytes();
    // The socket owner stays alive for the call. Winsock reads exactly the
    // four bytes of the interface index and retains no pointer to them.
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            bytes.as_ptr(),
            4,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}
