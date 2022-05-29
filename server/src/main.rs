mod action;
mod authentication;
mod connection;
mod database;
mod mailer;

#[macro_use]
extern crate lazy_static;

use crate::action::Action;
use crate::authentication::Authenticate;
use crate::connection::Connection;
use simple_logger::SimpleLogger;
use std::net::TcpListener;
use std::thread;

fn handle_client(mut connection: Connection) {
    loop {
        match Authenticate::perform(&mut connection) {
            Ok(Some(mut user)) => {
                while let Ok(true) = Action::perform(&mut user, &mut connection) {}
            }
            Err(_) => return,
            _ => {}
        }
    }
}

const SERVER_IP: &str = "127.0.0.1:8080";

fn main() {
    SimpleLogger::new().env().init().unwrap();

    log::info!("Staring server");

    let listener = TcpListener::bind(SERVER_IP).unwrap();

    log::info!("Server is UP.");
    log::info!("Serving clients on {}", SERVER_IP);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(Connection::new(stream));
                });
            }
            Err(e) => {
                println!("Connection failed with error: {}", e);
            }
        }
    }

    println!("Server DOWN.");
}
