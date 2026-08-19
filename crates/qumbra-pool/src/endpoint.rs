//! Plain TCP, one JSON-RPC object per LF-terminated line.
//!
//! Deliberately not `qlab-p2p` transport (framed binary) and not
//! `qlab-cbserver` HTTP. Steal discipline, not code — mapping doc §6.2.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qlab_stratum::codec::{encode_request, encode_response};
use qlab_stratum::types::job_notification;

use crate::pool::{Outgoing, Pool};

/// Bind and accept until `stop` is set. Each connection is a thread.
pub fn serve(listener: TcpListener, pool: Arc<Pool>, stop: Arc<AtomicBool>) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let pool = Arc::clone(&pool);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, pool, stop) {
                        qlab_devnet::jeprintln!("qumbra-pool conn: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn handle_conn(stream: TcpStream, pool: Arc<Pool>, stop: Arc<AtomicBool>) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut session: Option<String> = None;
    let mut line = String::new();
    while !stop.load(Ordering::SeqCst) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => match pool.handle_line(&mut session, &line) {
                Ok(out) => {
                    for item in out {
                        write_out(&mut writer, item)?;
                    }
                }
                Err(e) => {
                    let resp = qlab_stratum::types::StratumResponse::err(
                        0,
                        crate::pool::ERR_INVALID,
                        e.to_string(),
                    );
                    write_out(&mut writer, Outgoing::Reply(resp))?;
                }
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn write_out(w: &mut TcpStream, item: Outgoing) -> std::io::Result<()> {
    let bytes = match item {
        Outgoing::Reply(resp) => encode_response(&resp).map_err(std::io::Error::other)?,
        Outgoing::Notify(req) => encode_request(&req).map_err(std::io::Error::other)?,
    };
    w.write_all(bytes.as_bytes())?;
    w.flush()
}

/// Encode a job as a stratum notification line (endpoint / tests).
pub fn encode_job_notify(job: &qlab_stratum::types::Job) -> Result<String, std::io::Error> {
    let req = job_notification(job).map_err(std::io::Error::other)?;
    encode_request(&req).map_err(std::io::Error::other)
}
