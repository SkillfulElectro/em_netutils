///! all the functions notify their state with EMNetSSErrors enum
use core::ffi::{c_char, c_int, c_void, CStr};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};

#[repr(C)]
enum EMNetSSErrors {
    Success = 0,
    NullbufferPassed = -1,
    CouldNotReadThebuffer = -2,
    NullHandlePassed = -5,
    NoStreamAccepted = -6,
    FailedToWriteToSocket = -11,
    FailedToConnectOrBindToIPV4 = -12,
    FailedToGetSocketsOrServersInfo = -15,
}

#[no_mangle]
/// starts the tcp server on ipv4 and port and fills server_handle with handle to the
/// tcp server in Rust side
pub extern "C" fn em_host_tcp_server(
    ipv4_port: *const c_char,
    server_handle: *mut *mut c_void,
) -> c_int {
    if server_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    if ipv4_port.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    let c_str = unsafe { CStr::from_ptr(ipv4_port) };
    let ipv4_port = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return EMNetSSErrors::CouldNotReadThebuffer as c_int,
    };

    match TcpListener::bind(ipv4_port) {
        Ok(listener) => {
            let server_main = Arc::new(Mutex::new(listener));
            let server = Arc::into_raw(server_main);

            unsafe {
                *server_handle = server as *mut c_void;
            }

            EMNetSSErrors::Success as c_int
        }
        Err(_) => EMNetSSErrors::FailedToConnectOrBindToIPV4 as c_int,
    }
}

#[no_mangle]
/// accepts sockets and returns handle to them using socket handle
pub extern "C" fn em_accept_tcp_connection(
    server_handle: *mut c_void,
    get_ipv4_port: *mut c_char,
    get_ipv4_port_len: *mut c_int,
    socket_handle: *mut *mut c_void,
) -> c_int {
    if server_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let server_main = { unsafe { Arc::from_raw(server_handle as *const Mutex<TcpListener>) } };

    let server = Arc::clone(&server_main);

    let _ = Arc::into_raw(server_main);

    let server = match server.lock() {
        Ok(server) => server,
        Err(_) => return EMNetSSErrors::FailedToGetSocketsOrServersInfo as c_int,
    };

    match server.accept() {
        Ok((stream, sockaddr)) => {
            let stream_main = Arc::new(Mutex::new(stream));
            let stream = Arc::into_raw(stream_main);

            unsafe {
                *socket_handle = stream as *mut c_void;
            }

            if !get_ipv4_port_len.is_null() {
                let get_ipv4_port_len: &mut c_int = unsafe { &mut *get_ipv4_port_len };
                if *get_ipv4_port_len > 0 && !get_ipv4_port.is_null() {
                    let sockaddr_str = sockaddr.to_string();
                    let sockaddr_bytes = sockaddr_str.as_bytes();
                    let mut new_len = 0;
                    unsafe {
                        for index in 0..(*get_ipv4_port_len) {
                            if !(index < sockaddr_bytes.len() as c_int) {
                                break;
                            }
                            *get_ipv4_port.add(index as usize) =
                                sockaddr_bytes[index as usize] as c_char;
                            new_len += 1;
                        }
                    }
                    *get_ipv4_port_len = new_len as c_int;
                }
            }

            EMNetSSErrors::Success as c_int
        }
        Err(_) => EMNetSSErrors::NoStreamAccepted as c_int,
    }
}

#[no_mangle]
/// reads the data from socket , and updates the buffer_len with len of data it read
/// buffer_len == zero -> disconnected
pub extern "C" fn em_read_from_tcp_connection(
    buffer: *mut c_char,
    buffer_len: *mut usize,
    socket_handle: *mut c_void,
) -> c_int {
    if buffer.is_null() || buffer_len.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let buffer_len: &mut usize = unsafe { &mut *buffer_len };

    let buf_slice: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, *buffer_len) };

    let stream_main = unsafe { Arc::from_raw(socket_handle as *const Mutex<TcpStream>) };

    let stream = Arc::clone(&stream_main);

    let _ = Arc::into_raw(stream_main);

    let mut stream: std::sync::MutexGuard<'_, TcpStream> = match stream.lock() {
        Ok(stream) => stream,
        Err(_) => return EMNetSSErrors::FailedToGetSocketsOrServersInfo as c_int,
    };

    match stream.read(buf_slice) {
        Ok(bytes_written) => {
            *buffer_len = bytes_written;
            bytes_written as c_int
        }
        Err(_) => EMNetSSErrors::FailedToWriteToSocket as c_int,
    }
}

#[no_mangle]
/// writes the data to socket , and updates the buffer_len with len of data it read
pub extern "C" fn em_write_to_the_tcp_connection(
    buffer: *const c_char,
    buffer_len: *mut usize,
    socket_handle: *mut c_void,
) -> c_int {
    if buffer.is_null() || buffer_len.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let buffer_len: &mut usize = unsafe { &mut *buffer_len };

    let buf_slice: &[u8] = unsafe { std::slice::from_raw_parts(buffer as *const u8, *buffer_len) };

    let stream_main = unsafe { Arc::from_raw(socket_handle as *const Mutex<TcpStream>) };

    let stream = Arc::clone(&stream_main);

    let _ = Arc::into_raw(stream_main);

    let mut stream: std::sync::MutexGuard<'_, TcpStream> = match stream.lock() {
        Ok(stream) => stream,
        Err(_) => return EMNetSSErrors::FailedToGetSocketsOrServersInfo as c_int,
    };

    match stream.write(buf_slice) {
        Ok(bytes_written) => {
            *buffer_len = bytes_written;
            bytes_written as c_int
        }
        Err(_) => EMNetSSErrors::FailedToWriteToSocket as c_int,
    }
}

#[no_mangle]
/// stops and closes tcp server
pub extern "C" fn em_stop_the_tcp_server(server_handle: *mut *mut c_void) -> c_int {
    if server_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    unsafe {
        if (*server_handle).is_null() {
            return EMNetSSErrors::NullHandlePassed as c_int;
        }
    }

    let _ = unsafe { Arc::from_raw(server_handle as *const Mutex<TcpListener>) };

    unsafe {
        *server_handle = std::ptr::null_mut();
    }

    EMNetSSErrors::Success as c_int
}

#[no_mangle]
/// stops and closes tcp socket
pub extern "C" fn em_close_the_tcp_connection(socket_handle: *mut *mut c_void) -> c_int {
    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    unsafe {
        if (*socket_handle).is_null() {
            return EMNetSSErrors::NullHandlePassed as c_int;
        }
    }

    let _ = unsafe { Arc::from_raw(socket_handle as *const Mutex<TcpStream>) };

    unsafe {
        *socket_handle = std::ptr::null_mut();
    }

    EMNetSSErrors::Success as c_int
}

#[no_mangle]
/// creates and connects tcp socket to the server
pub extern "C" fn em_connect_tcp_socket_to(
    ipv4_port: *const c_char,
    socket_handle: *mut *mut c_void,
) -> c_int {
    if ipv4_port.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    // Convert C string to Rust string
    let c_str = unsafe { CStr::from_ptr(ipv4_port) };

    let address = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return EMNetSSErrors::CouldNotReadThebuffer as c_int,
    };

    // Attempt to connect to the server
    match TcpStream::connect(address) {
        Ok(stream) => {
            let stream = Arc::new(Mutex::new(stream));

            unsafe {
                *socket_handle = Arc::into_raw(stream) as *mut c_void;
            }

            EMNetSSErrors::Success as c_int
        }
        Err(_) => EMNetSSErrors::FailedToConnectOrBindToIPV4 as c_int, // Connection failed
    }
}

#[no_mangle]
/// binds udp socket to ipv4 port and returns socket_handle
pub extern "C" fn em_bind_udp_socket(
    ipv4_port: *const c_char,
    socket_handle: *mut *mut c_void,
) -> c_int {
    if ipv4_port.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let c_str = unsafe { CStr::from_ptr(ipv4_port) };

    let ipv4_port = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return EMNetSSErrors::CouldNotReadThebuffer as c_int,
    };

    // Create and bind the UDP socket
    let socket = match UdpSocket::bind(ipv4_port) {
        Ok(socket) => socket,
        Err(_) => return EMNetSSErrors::FailedToConnectOrBindToIPV4 as c_int,
    };

    let socket = Arc::new(Mutex::new(socket));

    unsafe {
        *socket_handle = Arc::into_raw(socket) as *mut c_void;
    }

    EMNetSSErrors::Success as c_int
}

#[no_mangle]
/// writes the data from socket created using em_bind_udp_socket to host_udp_sock_addr
pub extern "C" fn em_write_to_udp_socket(
    host_udp_sock_addr: *const c_char,
    socket_handle: *mut c_void,
    buffer: *mut c_char,
    buffer_len: *mut usize,
) -> c_int {
    if buffer.is_null() || buffer_len.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let stream_main = unsafe { Arc::from_raw(socket_handle as *const Mutex<UdpSocket>) };

    let socket = Arc::clone(&stream_main);

    let _ = Arc::into_raw(stream_main);

    let socket = match socket.lock() {
        Ok(socket) => socket,
        Err(_) => return EMNetSSErrors::FailedToGetSocketsOrServersInfo as c_int,
    };

    let buffer_len: &mut usize = unsafe { &mut *buffer_len };

    // Convert the buffer to a string
    let buf_slice: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, *buffer_len) };

    let ipv4_port = unsafe { CStr::from_ptr(host_udp_sock_addr) };

    let ipv4_port = match ipv4_port.to_str() {
        Ok(s) => s,
        Err(_) => return EMNetSSErrors::CouldNotReadThebuffer as c_int,
    };
    // Send the buffer
    match socket.send_to(buf_slice, ipv4_port) {
        Ok(bytes_written) => {
            *buffer_len = bytes_written;
            bytes_written as c_int
        }
        Err(_) => return EMNetSSErrors::FailedToWriteToSocket as c_int, // Error
    }
}

#[no_mangle]
/// reads the data from socket_handle
pub extern "C" fn em_read_from_udp_socket(
    get_ipv4_port: *mut c_char,
    get_ipv4_port_len: usize,
    socket_handle: *mut c_void,
    buffer: *mut c_char,
    buffer_len: *mut usize,
) -> c_int {
    if buffer.is_null() || buffer_len.is_null() {
        return EMNetSSErrors::NullbufferPassed as c_int;
    }

    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    let stream_main = unsafe { Arc::from_raw(socket_handle as *const Mutex<UdpSocket>) };

    let socket = Arc::clone(&stream_main);

    let _ = Arc::into_raw(stream_main);

    let socket = match socket.lock() {
        Ok(socket) => socket,
        Err(_) => return EMNetSSErrors::FailedToGetSocketsOrServersInfo as c_int,
    };

    let buffer_len: &mut usize = unsafe { &mut *buffer_len };

    let mut buf: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, *buffer_len) };

    match socket.recv_from(&mut buf) {
        Ok((bytes_read, sockaddr)) => {
            if get_ipv4_port_len > 0 && !get_ipv4_port.is_null() {
                let sockaddr_str = sockaddr.to_string();
                let sockaddr_bytes = sockaddr_str.as_bytes();
                unsafe {
                    for index in 0..get_ipv4_port_len {
                        *get_ipv4_port.add(index as usize) =
                            sockaddr_bytes[index as usize] as c_char;
                    }
                }
            }

            *buffer_len = bytes_read;
            bytes_read as c_int
        }
        Err(_) => return EMNetSSErrors::CouldNotReadThebuffer as c_int,
    }
}

#[no_mangle]
/// stops and deallocates the udp socket_handle
pub extern "C" fn em_stop_udp_socket(socket_handle: *mut *mut c_void) -> c_int {
    if socket_handle.is_null() {
        return EMNetSSErrors::NullHandlePassed as c_int;
    }

    unsafe {
        if (*socket_handle).is_null() {
            return EMNetSSErrors::NullHandlePassed as c_int;
        }
    }

    unsafe {
        let _ = Arc::from_raw(*socket_handle as *const Mutex<UdpSocket>);
    }

    unsafe {
        *socket_handle = std::ptr::null_mut();
    }

    EMNetSSErrors::Success as c_int
}
