//! Plain TCP, one JSON-RPC object per LF-terminated line.
//!
//! Deliberately not `qlab-p2p` transport (framed binary) and not
//! `qlab-cbserver` HTTP. Steal discipline, not code — mapping doc §6.2.
//!
//! Job re-issue (lab #545): a shared latest-value [`JobOutbox`] is the
//! path from the poll thread to each connection's writer. The accept
//! loop stays thread-per-connection; each thread drains its session's
//! slot on the read timeout (and after every request) so a tip change
//! does not wait on the miner to speak.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qlab_stratum::codec::{encode_request, encode_response};
use qlab_stratum::types::{job_notification, StratumResponse};

use crate::outbox::{JobOutbox, SessionPush};
use crate::pool::{Outgoing, Pool, ERR_INVALID};

/// Wake often enough that a pushed job is not stuck behind a long read.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Bind and accept until `stop` is set. Each connection is a thread.
///
/// `outbox` is installed on `pool` so [`Pool::replace_template`] deposits
/// jobs where this loop can drain them. Tests that do not re-issue can
/// pass a fresh empty outbox.
pub fn serve(
    listener: TcpListener,
    pool: Arc<Pool>,
    stop: Arc<AtomicBool>,
    outbox: Arc<JobOutbox>,
) -> std::io::Result<()> {
    pool.set_outbox(Arc::clone(&outbox));
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let pool = Arc::clone(&pool);
                let stop = Arc::clone(&stop);
                let outbox = Arc::clone(&outbox);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, pool, stop, outbox) {
                        qlab_devnet::jeprintln!(WARN, "qumbra-pool conn: {e}");
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

fn handle_conn(
    stream: TcpStream,
    pool: Arc<Pool>,
    stop: Arc<AtomicBool>,
    outbox: Arc<JobOutbox>,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut session: Option<String> = None;
    let mut registered: Option<String> = None;
    let mut line = String::new();
    let result = loop {
        if stop.load(Ordering::SeqCst) {
            break Ok(());
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break Ok(()),
            Ok(_) => match pool.handle_line(&mut session, &line) {
                Ok(out) => {
                    sync_registration(&pool, &outbox, &session, &mut registered);
                    for item in out {
                        write_out(&mut writer, item)?;
                    }
                    if !drain_outbox(&mut writer, &outbox, registered.as_deref())? {
                        break Ok(());
                    }
                }
                Err(e) => {
                    let resp = StratumResponse::err(0, ERR_INVALID, e.to_string());
                    write_out(&mut writer, Outgoing::Reply(resp))?;
                }
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !drain_outbox(&mut writer, &outbox, registered.as_deref())? {
                    break Ok(());
                }
            }
            Err(e) => break Err(e),
        }
    };
    if let Some(sid) = registered.take() {
        outbox.unregister(&sid);
        pool.drop_session(&sid);
    }
    result
}

fn sync_registration(
    pool: &Pool,
    outbox: &JobOutbox,
    session: &Option<String>,
    registered: &mut Option<String>,
) {
    if session.as_deref() == registered.as_deref() {
        return;
    }
    if let Some(old) = registered.take() {
        outbox.unregister(&old);
        pool.drop_session(&old);
    }
    if let Some(sid) = session.as_ref() {
        outbox.register(sid.clone());
        *registered = Some(sid.clone());
    }
}

/// Drain this session's outbox slot. `Ok(false)` means the pool asked
/// us to disconnect after writing a named stop.
fn drain_outbox(
    writer: &mut TcpStream,
    outbox: &JobOutbox,
    sid: Option<&str>,
) -> std::io::Result<bool> {
    let Some(sid) = sid else {
        return Ok(true);
    };
    match outbox.take(sid) {
        Some(SessionPush::Job(job)) => {
            let req = job_notification(&job).map_err(std::io::Error::other)?;
            write_out(writer, Outgoing::Notify(req))?;
            Ok(true)
        }
        Some(SessionPush::Unavailable(reason)) => {
            write_out(
                writer,
                Outgoing::Reply(StratumResponse::err(0, ERR_INVALID, reason)),
            )?;
            Ok(false)
        }
        None => Ok(true),
    }
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
