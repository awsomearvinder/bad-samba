use std::io;

use smb2::message::SmbNegotiate;

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:445").await?;
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let mut buffer = vec![0; 1024];
                socket.readable().await;
                socket
                    .try_read_buf(&mut buffer)
                    .expect("failed to read buffer");
                println!("{:?}", buffer);
                let (remaining, header) =
                    smb::message::SmbMessageHeader::try_parse(&buffer).unwrap();
                println!("{header:?}");
                let negotiate = match header.protocol_id {
                    0 => SmbNegotiate::parse(remaining).unwrap(),
                    _ => todo! {},
                };
                println!("{:?}", negotiate);
            }
            Err(e) => println!("Couldn't get client {:?}", e),
        }
    }
}
