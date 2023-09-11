use std::io;

use smb::Smb1Message;
use smb2::message::SmbMessage;

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:445").await?;
    loop {
        let mut len = [0; 4];
        let mut buf = Vec::new();
        match listener.accept().await {
            Ok((socket, _addr)) => {
                socket.readable().await.unwrap();
                socket.try_read(&mut len).expect("failed to read buffer");
                let len = u32::from_be_bytes(len).try_into().unwrap();
                buf.resize(len, 0);
                socket.try_read(&mut buf).unwrap();
                let negotiate = SmbMessage::try_parse(&buf);
                println!("SMB2: {:?}", negotiate);
                let negotiate = Smb1Message::try_parse(&buf);
                println!("SMB: {:?}", negotiate);
            }
            Err(e) => println!("Couldn't get client {:?}", e),
        }
    }
}
