use std::net::{SocketAddr, IpAddr};
use socket2::{Socket, Domain, Type, SockAddr, Protocol};
use std::{thread, time, process, env};
use std::time::{SystemTime, UNIX_EPOCH};
extern crate hex;

// Debug purposes - Rust cannot easily print an array over 32 elements
fn print_array(array: &[u8]) {
    for element in array.iter() {
        print!("{:02x}", element);
    }
    println!("");
}

// Puts a u16 in network order (htons "replacement")
fn put_u16(array: &mut [u8], index: usize, value: u16) {
    array[index] = value as u8;
    array[index + 1] = (value >> 8usize) as u8;
}

// Gets a u16 from array
fn get_u16(array: &[u8], index: usize) -> Result<u16, &'static str> {
    if index + 1 >= array.len() {
        return Err("Out of bounds");
    }
    let x = (array[index] as u16) | ((array[index + 1] as u16) << 8usize);
    Ok(x)
}

// Puts a u128 into array
fn put_u128(array: &mut [u8], index: usize, value: u128) {
    for i in 0..16 {
        array[index + i] = (value >> (8usize * i)) as u8;
    }
}

// Gets a u128 from array
fn get_u128(array: &[u8], index: usize) -> Result<u128, &'static str> {
    if index + 15 >= array.len() {
        return Err("Out of bounds");
    }
    let mut value = 0u128;
    for i in 0..16 {
        value |= (array[index + i] as u128) << (8usize * i);
    }
    Ok(value)
}

// Currently only works for even number of elements
fn calc_checksum(array: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    let mut length = array.len();
    while length > 1 {
        sum += ((array[index + 1] as u32) << 8) | (array[index] as u32);
        length -= 2;
        index += 2;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    (!sum) as u16
}

// Timestamp to be put in the packet
fn get_time_in_nanos() -> u128 {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_nanos()
}

struct IpAddrTypeInfo {
    domain: Domain,
    protocol: Protocol,
    echo_request_type: u8,
    echo_reply_type: u8,
    header_offset: usize,
    ttl_offset: usize,
    packet_size: usize,
}

struct Config {
    ip: IpAddr,
    ttl: u32,
}

impl Config {
    fn new(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        }
        let ip_string = &args[1];
        let ip = match ip_string.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_e) => return Err("Failed to parse Ip Address")
        };
        if args.len() >= 3 {
            let ttl_string = &args[2];
            let ttl = match ttl_string.parse::<u32>() {
                Ok(ttl) => ttl,
                Err(_e) => return Err("Failed to parse TTL")
            };
            return Ok(Config {ip, ttl})
        } else {
            return Ok(Config {ip, ttl: 64})
        }
    }
}

// Stores Ping Packet information
struct PingPacket {
    identifier: u16,
    sequence_number: u16,
    timestamp: u128,
}

impl PingPacket {
    // Creates a ping packet with current time
    fn new(identifier: u16, sequence_number: u16) -> PingPacket {
        PingPacket {identifier, sequence_number, timestamp: get_time_in_nanos()}
    }
    // Creates a ping packet from a byte array
    fn from(offset: usize, array: &[u8]) -> Result<PingPacket, &'static str> {
        let identifier = get_u16(array, offset + 4)?;
        let sequence_number = get_u16(array, offset + 6)?;
        let timestamp = get_u128(array, offset + 8)?;
        Ok(PingPacket {identifier, sequence_number, timestamp})
    }
    // Creates a 44 byte array from this packet
    fn to_byte_array(&self, packet_type: u8) -> [u8; 44] {
        let mut packet = [0u8; 44];
        self.fill_array(&mut packet, packet_type);
        packet
    }
    // Fills array with apropriate info
    fn fill_array(&self, packet: &mut [u8], packet_type: u8) {
        // header
        packet[0] = packet_type; // type: echo request
        packet[1] = 0; // code: 0
        put_u16(packet, 4, self.identifier);
        put_u16(packet, 6, self.sequence_number);
        // payload
        put_u128(packet, 8, self.timestamp);
        // checksum
        let checksum = calc_checksum(packet);
        put_u16(packet, 2, checksum);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::new(&args).unwrap_or_else(|err| {
        println!("Unable to parse arguments: {}", err);
        println!("Format: {} <ip> [ttl]", args[0]);
        process::exit(1);
    });
    println!("Pinging Ip Address: {}, ttl={}", config.ip, config.ttl);

    // Constants taken from: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    let ip_addr_type_info = match config.ip {
        IpAddr::V4(_) => IpAddrTypeInfo {
            domain: Domain::ipv4(),
            protocol: Protocol::icmpv4(),
            echo_request_type: 8,
            echo_reply_type: 0,
            header_offset: 20,
            ttl_offset: 8,
            packet_size: 44,
        },
        IpAddr::V6(_) => IpAddrTypeInfo {
            domain: Domain::ipv6(),
            protocol: Protocol::icmpv6(),
            echo_request_type: 128,
            echo_reply_type: 129,
            header_offset: 40,
            ttl_offset: 7,
            packet_size: 24,
        },
    };

    let socket = Socket::new(ip_addr_type_info.domain, Type::raw(), Some(ip_addr_type_info.protocol))
        .expect("Unable to create new socket");
    
    // Set TTL
    match config.ip {
        IpAddr::V4(_) => socket.set_ttl(config.ttl)
            .expect("Failed to set TTL"), // IPv4
        IpAddr::V6(_) => socket.set_unicast_hops_v6(config.ttl)
            .expect("Failed to set TTL"), // IPv6
    }
    let socket_address = SocketAddr::new(config.ip, 0); // Port 0 because port doesn't matter for raw sockets
    let socket_address = SockAddr::from(socket_address); // rust shadowing

    let mut buffer = [0u8; 64];
    let identifier = process::id() as u16;
    let mut successful_counter = 0u16;
    let mut counter = 1u16;
    loop {
        let payload = PingPacket::new(identifier, counter)
            .to_byte_array(ip_addr_type_info.echo_request_type);

        let sliced_payload = &payload[..ip_addr_type_info.packet_size];
        let send_result = socket.send_to(sliced_payload, &socket_address);
        match send_result {
            Err(_) | Ok(0) => {
                print!("Failed to send payload to {}: ", config.ip);
                print_array(sliced_payload);
                continue;
            },
            _ => {},
        };

        // Read packets until we find our own packet
        let (received_packet, bytes_read) = loop {
            let (bytes_read, _address) = socket.recv_from(&mut buffer)
                .expect("Failed to read packet");
            let packet = PingPacket::from(ip_addr_type_info.header_offset, &buffer)
                .expect("Failed to parse packet");
            if packet.identifier == identifier {
                break (packet, bytes_read);
            }
        };

        // Check if we successfully received echo reply
        if buffer[ip_addr_type_info.header_offset] == ip_addr_type_info.echo_reply_type {
            successful_counter += 1;
        }

        // Print info
        let ttl = buffer[ip_addr_type_info.ttl_offset];
        let elapsed_time = (get_time_in_nanos() - received_packet.timestamp) as f64;
        let elapsed_time = elapsed_time / 1000000f64;
        let loss_percentage = ((counter - successful_counter) as f64) / (counter as f64) * 100f64;
        println!("{} bytes from {}: icmp_seq={} ttl={} time={:.2}ms loss={:.2}%",
                 bytes_read, config.ip, received_packet.sequence_number, ttl, elapsed_time, loss_percentage);

        // Sleep & Increment Counter
        thread::sleep(time::Duration::from_millis(1000));
        counter += 1;
    }
}
