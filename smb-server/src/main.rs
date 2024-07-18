use std::io;
use std::num::NonZeroU64;
use std::sync::Arc;

use smb::{Smb1Header, Smb1Message};
use smb2::message::SmbNegotiateResponse;
use smb2::message::{SmbMessage, SmbMessageHeader, SmbMessageHeaderVariant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::Mutex;

struct Server;

impl Server {
    async fn handle_message(&mut self, message: &SmbMessage) {}
    async fn handle_smb1_message(&mut self, message: &Smb1Message) -> SmbMessage {
        match &message.body {
            // for now we only are going to support SMB 2.???
            smb::Smb1Body::SmbComNegotiate(a) => SmbMessage {
                header: SmbMessageHeader {
                    protocol_id: u32::from_ne_bytes([0xFE, b'S', b'M', b'B']),
                    header_size: 64,
                    credit_charge: 0,
                    status: 0,
                    command: 0,
                    credit_request_response: 0,
                    flags: 0x1 & 0x2,
                    next_command: 0,
                    message_id: 14123141,
                    variant: SmbMessageHeaderVariant::Async {
                        id: NonZeroU64::new(12).unwrap(),
                    },
                    session_id: 0,
                    signature: 0,
                },
                body: smb2::message::SmbBody::NegotiateResponse(SmbNegotiateResponse {
                    size: 65,
                    security_mode: 0x01,
                    dialect_rev: 0x02FF,
                    negotiate_context_count: 0,
                    server_guid: 23885548255760334674942869530154890271,
                    capabilities: 0,
                    max_transact_size: 120,
                    max_read_size: 120,
                    max_write_size: 120,
                    system_time: 13364930937000000,
                    server_start_time: 5,
                    security_buff_offset: 0,
                    security_buff_len: 0,
                    neg_context_offset: 0,
                    buf: vec![],
                    context_list: vec![],
                }),
            },
        }
    }
}

async fn handle_conn(server: Arc<Mutex<Server>>, mut socket: TcpStream) {
    let mut len = [0; 4];
    let mut buf = Vec::new();
    loop {
        socket.readable().await.unwrap();
        socket.read(&mut len).await.expect("failed to read buffer");
        let len = u32::from_be_bytes(len).try_into().unwrap();
        buf.resize(len, 0);
        socket.read(&mut buf).await.unwrap();
        if let Ok((_remaining, message)) = SmbMessage::try_parse(&buf) {
            let mut server = server.lock().await;
            server.handle_message(dbg!(&message)).await;
        } else if let Ok((_remaining, message)) = Smb1Message::try_parse(&buf) {
            let mut server = server.lock().await;
            let resp = server.handle_smb1_message(dbg!(&message)).await;
            let buff = resp.to_vec();
            let mut buff2 = vec![];
            buff2.extend(u32::to_be_bytes(buff.len() as u32));
            buff2.extend(buff);
            socket.writable().await.unwrap();
            socket.write(&buff2).await.unwrap();
            println!("sent response!");
        } else {
            println!("error {:x?}", &buf);
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:445").await?;
    let server = Arc::new(Mutex::new(Server));
    loop {
        match listener.accept().await {
            Ok((socket, _addr)) => {
                tokio::spawn(handle_conn(server.clone(), socket));
                // println!("SMB: {:?}", negotiate.unwrap().1.body);
            }
            Err(e) => println!("Couldn't get client {:?}", e),
        }
    }
}
