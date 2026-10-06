// A prompter reached over a unix socket instead of the session bus.
//
// GNOME's and Plasma's prompters are services on the session bus, which any
// program of the user can also answer. This one is a unix socket given on the
// command line (`--prompter-socket`), so whoever may open it is decided by the
// file system, and the prompter can run as another user than the clients.
//
// The daemon connects once per prompt and speaks JSON lines, one request then
// one reply, as many times as the prompt needs (an unlock asks again after a
// wrong password, an unlock can be followed by an access request). It closes
// the connection when the prompt is over or dismissed by its client: a
// prompter that sees EOF closes its dialog.
//
// Request, daemon to prompter:
//
//   {"version":1,"type":"unlock","keyring":"Login","prompt":"/org/freedesktop/secrets/prompt/p1",
//    "warning":"The unlock password was incorrect",
//    "caller":{"bus_name":":1.42","pid":1234,"pidfd":true}}
//   {"version":1,"type":"create","keyring":"Login",...}
//   {"version":1,"type":"unlock","keyring":"Login","operation":"read",...}
//   {"version":1,"type":"access","keyring":"Login","operation":"read","items":["GitHub token"],...}
//
// - `type`: `unlock` asks for the password of an existing keyring, `create`
//   for the password of a keyring that does not exist yet, `access` asks
//   whether the caller may use `items` (their labels) for `operation` (`read`
//   or `delete`).
// - `operation` on an `unlock` or `create` request: the password also allows
//   the caller to `read` the items it asked for, with no `access` request
//   after it; the dialog must then name the caller as an access dialog does.
// - `prompt` is absent when the daemon asks on its own, without a Prompt object
//   (a search that found the keyring locked).
// - `warning` is absent on the first try.
// - `caller` is the client that asked: its unique bus name and pid as the bus
//   gives them. With `"pidfd":true`, the line comes with the caller's pidfd as
//   SCM_RIGHTS ancillary data, on every request line: the pid can be reused,
//   the pidfd cannot, so the prompter names the program from the pidfd.
//
// Reply, prompter to daemon:
//
//   {"result":"allow"}      the access request is allowed
//   {"result":"deny"}       refused, cancelled or timed out: the prompt is dismissed
//   {"result":"password"}   with one fd as SCM_RIGHTS: the read end of a unix
//                           stream socket the password is read from until EOF,
//                           as Plasma's and the CLI prompter hand it over, so it
//                           never sits in a JSON line; taken as is, a trailing
//                           newline would be part of it
//
// Anything else, EOF or no reply within PROMPT_TIMEOUT counts as `deny`.

use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
    time::Duration,
};

use oo7::Secret;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, Interest},
    net::UnixStream,
};
use zbus::names::OwnedUniqueName;

const PROTOCOL_VERSION: u32 = 1;

/// How long one request may wait for its reply. The prompter is expected to
/// time its dialogs out sooner; this only frees the daemon from a prompter that
/// hangs.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// The longest reply line, and the longest password, read from the prompter.
const MAX_REPLY: usize = 64 * 1024;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RequestType {
    Unlock,
    Create,
    Access,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Read,
    Delete,
}

/// The client a prompt is for, as the bus describes it.
#[derive(Debug, Default)]
pub struct Caller {
    pub bus_name: Option<OwnedUniqueName>,
    pub pid: Option<u32>,
    pub pidfd: Option<OwnedFd>,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub type_: RequestType,
    pub keyring: &'a str,
    pub prompt: Option<&'a str>,
    pub warning: Option<&'a str>,
    pub operation: Option<Operation>,
    pub items: &'a [String],
}

impl<'a> Request<'a> {
    pub fn password(type_: RequestType, keyring: &'a str, prompt: Option<&'a str>) -> Self {
        Self {
            type_,
            keyring,
            prompt,
            warning: None,
            operation: None,
            items: &[],
        }
    }

    pub fn access(
        keyring: &'a str,
        prompt: Option<&'a str>,
        operation: Operation,
        items: &'a [String],
    ) -> Self {
        Self {
            type_: RequestType::Access,
            keyring,
            prompt,
            warning: None,
            operation: Some(operation),
            items,
        }
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    version: u32,
    #[serde(rename = "type")]
    type_: RequestType,
    keyring: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<Operation>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    items: &'a [String],
    caller: WireCaller<'a>,
}

#[derive(Serialize)]
struct WireCaller<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    bus_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    pidfd: bool,
}

#[derive(Deserialize)]
struct WireReply {
    result: String,
}

#[derive(Debug)]
pub enum Reply {
    Allow,
    Deny,
    Password(Secret),
}

/// One prompt's connection to the prompter.
#[derive(Debug)]
pub struct Session {
    stream: UnixStream,
    caller: Caller,
    /// Bytes read past the end of the last reply line.
    pending: Vec<u8>,
}

impl Session {
    pub async fn connect(path: &Path, caller: Caller) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            stream,
            caller,
            pending: Vec::new(),
        })
    }

    /// Send a request and wait for its reply. A failure to talk to the
    /// prompter is an error; anything the prompter answers that is not an
    /// allow or a password is a `Deny`.
    pub async fn ask(&mut self, request: &Request<'_>) -> io::Result<Reply> {
        match tokio::time::timeout(PROMPT_TIMEOUT, self.ask_inner(request)).await {
            Ok(reply) => reply,
            Err(_) => {
                tracing::warn!("The prompter did not answer in {PROMPT_TIMEOUT:?}");
                Ok(Reply::Deny)
            }
        }
    }

    async fn ask_inner(&mut self, request: &Request<'_>) -> io::Result<Reply> {
        let wire = WireRequest {
            version: PROTOCOL_VERSION,
            type_: request.type_,
            keyring: request.keyring,
            prompt: request.prompt,
            warning: request.warning,
            operation: request.operation,
            items: request.items,
            caller: WireCaller {
                bus_name: self.caller.bus_name.as_ref().map(|n| n.as_str()),
                pid: self.caller.pid,
                pidfd: self.caller.pidfd.is_some(),
            },
        };
        let mut line = serde_json::to_vec(&wire).map_err(io::Error::other)?;
        line.push(b'\n');
        send_line(
            &self.stream,
            &line,
            self.caller.pidfd.as_ref().map(|fd| fd.as_fd()),
        )
        .await?;

        let Some((line, mut fds)) = read_line(&self.stream, &mut self.pending).await? else {
            tracing::debug!("The prompter closed the connection");
            return Ok(Reply::Deny);
        };
        let reply = match serde_json::from_slice::<WireReply>(&line) {
            Ok(reply) => reply,
            Err(err) => {
                tracing::warn!("Unreadable reply from the prompter: {err}");
                return Ok(Reply::Deny);
            }
        };

        match (reply.result.as_str(), request.type_) {
            ("allow", RequestType::Access) => Ok(Reply::Allow),
            ("password", RequestType::Unlock | RequestType::Create) if fds.len() == 1 => {
                let fd = fds.pop().unwrap();
                Ok(Reply::Password(read_secret(fd).await?))
            }
            ("deny", _) => Ok(Reply::Deny),
            (result, type_) => {
                tracing::warn!(
                    "Unexpected reply `{result}` with {} fd(s) to a {type_:?} request",
                    fds.len()
                );
                Ok(Reply::Deny)
            }
        }
    }
}

/// Write `line` to `stream`, with `fd` as SCM_RIGHTS on its first byte.
pub(crate) async fn send_line(
    stream: &UnixStream,
    line: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let mut written = 0;
    while written < line.len() {
        let rest = &line[written..];
        written += stream
            .async_io(Interest::WRITABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut control = SendAncillaryBuffer::new(&mut space);
                let fds = fd.map(|fd| [fd]);
                if written == 0
                    && let Some(fds) = &fds
                {
                    control.push(SendAncillaryMessage::ScmRights(fds));
                }
                sendmsg(
                    stream,
                    &[IoSlice::new(rest)],
                    &mut control,
                    SendFlags::NOSIGNAL,
                )
                .map_err(io::Error::from)
            })
            .await?;
    }
    Ok(())
}

/// Read one line from `stream` and the fds that came with it, keeping in
/// `pending` what was read past its end. `None` on EOF before a full line.
pub(crate) async fn read_line(
    stream: &UnixStream,
    pending: &mut Vec<u8>,
) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let mut fds = Vec::new();
    loop {
        if let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line = pending.drain(..=end).collect::<Vec<_>>();
            return Ok(Some((line, fds)));
        }
        if pending.len() > MAX_REPLY {
            return Err(io::Error::other("The line is too long"));
        }

        let mut buf = [0u8; 4096];
        let read = stream
            .async_io(Interest::READABLE, || {
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
                let mut control = RecvAncillaryBuffer::new(&mut space);
                let msg = recvmsg(
                    stream,
                    &mut [IoSliceMut::new(&mut buf)],
                    &mut control,
                    RecvFlags::CMSG_CLOEXEC,
                )
                .map_err(io::Error::from)?;
                for message in control.drain() {
                    if let RecvAncillaryMessage::ScmRights(received) = message {
                        fds.extend(received);
                    }
                }
                Ok(msg.bytes)
            })
            .await?;
        if read == 0 {
            return Ok(None);
        }
        pending.extend_from_slice(&buf[..read]);
    }
}
async fn read_secret(fd: OwnedFd) -> io::Result<Secret> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    let mut secret = zeroize::Zeroizing::new(Vec::new());
    stream
        .take(MAX_REPLY as u64)
        .read_to_end(&mut secret)
        .await?;
    Ok(Secret::from(secret.to_vec()))
}
