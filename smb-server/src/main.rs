use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:445").await?;
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => println!("new client {:?}", addr),
            Err(e) => println!("Couldn't get client {:?}", e),
        }
    }
}
