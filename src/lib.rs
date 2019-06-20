mod util;

use regex::Regex;
use std::{
    io::{prelude::*, BufReader},
    net::{TcpStream, ToSocketAddrs},
    ops::Deref,
};

type TlsStream = rustls::StreamOwned<rustls::ClientSession, TcpStream>;

pub struct PopStream {
    pub is_authenticated: bool,
    pub stream:           TlsStream,
}

impl PopStream {
    pub fn connect<A: ToSocketAddrs>(addr: A, sess: rustls::ClientSession) -> PopStream {
        let socket = TcpStream::connect(addr).expect(womp!());
        let owned = rustls::StreamOwned::new(sess, socket);
        let mut this = PopStream {
            is_authenticated: false,
            stream:           owned,
        };
        dbg!(this.read_response_line());
        this
    }

    pub fn write(&mut self, msg: &str) -> Result<(), std::io::Error> {
        let comm = dbg!(format!("{}\n", msg));
        self.stream.write_all(comm.as_bytes())?;
        Ok(())
    }

    pub fn stat(&mut self) -> Result<Stat, String> {
        self.write("STAT").expect(womp!());
        let resp = self.read_response_line();
        resp_code!(resp);
        let captures = capture!(r"(?P<msgs>[\d]+) (?P<oct>[\d]+)", &resp.first_line);
        // let captures = regex.captures(&resp.first_line).expect(womp!());
        assert_eq!(captures.len(), 2);
        Ok(Stat {
            num_messages: parse_match!(captures, "msgs"),
            size_octets:  parse_match!(captures, "oct"),
        })
    }

    pub fn read_scan(&mut self) -> Scan {
        let line = self.read_line();
        let captures = capture!(r"(?P<id>[\d]+) (?P<oct>[\d]+)", &line);
        Scan {
            id:     parse_match!(captures, "id"),
            octets: parse_match!(captures, "oct"),
        }
    }

    pub fn list_all(&mut self) -> Result<List, String> {
        self.write("LIST").expect(womp!());
        let resp = dbg!(self.read_response_line());
        resp_code!(resp);
        let captures = capture!(r"(?P<count>[\d]+) .*(?P<octs>[\d]+)", &resp.first_line);
        let count = parse_match!(captures, "count");
        let octets = parse_match!(captures, "octs");
        let mut scans = Vec::with_capacity(count as usize);
        for _ in 0..count {
            scans.push(self.read_scan());
        }
        Ok(List {
            count,
            octets,
            scans,
        })
    }

    pub fn list_one(&mut self, id: u64) -> Result<Scan, String> {
        self.write(&format!("LIST {}", id)).expect(womp!());
        let resp = self.read_response_line();
        resp_code!(resp);
        let captures = capture!(r"(?P<id>[\d]+) (?P<oct>[\d]+)", &resp.first_line);
        Ok(Scan {
            id:     parse_match!(captures, "id"),
            octets: parse_match!(captures, "oct"),
        })
    }

    pub fn retr(&mut self, id: u64) -> Result<Vec<String>, String> {
        self.write(&format!("RETR {}", id)).expect(womp!());
        let resp = self.read_response_to_end();
        resp_code!(resp);
        Ok(resp.lines)
    }

    pub fn dele(&mut self, id: u64) -> PopResponse {
        self.write(&format!("DELE {}", id)).expect(womp!());
        self.read_response_line()
    }

    pub fn noop(&mut self) -> PopResponse {
        self.write("NOOP").expect(womp!());
        self.read_response_line()
    }

    pub fn rset(&mut self) -> PopResponse {
        self.write("RSET").expect(womp!());
        self.read_response_line()
    }

    pub fn quit(&mut self) -> PopResponse {
        self.write("QUIT").expect(womp!());
        self.read_response_line()
    }

    pub fn user(&mut self, user: &str) -> PopResponse {
        let command = format!("USER {}", user);
        self.write(&command).expect(womp!());
        self.read_response_line()
    }

    pub fn pass(&mut self, user: &str) -> PopResponse {
        self.write(&format!("PASS {}", user)).expect(womp!());
        self.read_response_line()
    }

    pub fn login(&mut self, user: &str, pass: &str) -> (PopResponse, PopResponse) {
        let resp1 = self.user(user);
        let resp2 = self.pass(pass);
        if resp1.success && resp2.success {
            self.is_authenticated = true;
        }
        dbg!((resp1, resp2))
    }

    fn read_ok_err(&mut self) -> bool {
        let mut buf = vec![0; 1];
        self.stream.read_exact(&mut buf).expect(womp!());
        match buf.deref() {
            b"+" => {
                buf = vec![0; 2];
                self.stream.read_exact(&mut buf).expect(womp!());
                assert_eq!(&buf, b"OK");
                true
            }
            b"-" => {
                buf = vec![0; 3];
                self.stream.read_exact(&mut buf).expect(womp!());
                assert_eq!(&buf, b"ERR");
                false
            }
            e => panic!("BAD RESPONSE: expected [+|-], found {:x?}", e),
        }
    }

    fn read_line(&mut self) -> String {
        let stream = rustls::Stream::new(&mut self.stream.sess, &mut self.stream.sock);
        let mut bufread = BufReader::new(stream);
        let mut buf = String::new();
        bufread.read_line(&mut buf).expect(womp!());
        assert_eq!(buf.pop(), Some('\n'));
        assert_eq!(buf.pop(), Some('\r'));
        buf
    }

    fn read_response_line(&mut self) -> PopResponse {
        let success = self.read_ok_err();
        let first_line = self.read_line();
        PopResponse {
            success,
            first_line,
            lines: vec![],
        }
    }

    fn read_response_to_end(&mut self) -> PopResponse {
        let mut resp = self.read_response_line();
        if resp.success {
            let mut nextline = self.read_line();
            while &nextline != "." {
                resp.lines.push(nextline);
                nextline = self.read_line();
            }
        }
        resp
    }
}

#[derive(Clone, Debug)]
pub struct PopResponse {
    pub success:    bool,
    pub first_line: String,
    pub lines:      Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Stat {
    num_messages: u64,
    size_octets:  u64,
}

#[derive(Clone, Debug)]
pub struct List {
    count:  u64,
    octets: u64,
    scans:  Vec<Scan>,
}

#[derive(Clone, Debug)]
pub struct Scan {
    id:     u64,
    octets: u64,
}

#[derive(Clone, Debug)]
pub struct Retr {
    bytes: Vec<u8>,
}

/// List of POP3 Commands
#[derive(Clone, Debug)]
pub enum PopCommand {
    Greet,
    User(String),
    Pass(String),
    Stat,
    UidlAll,
    UidlOne,
    ListAll,
    ListOne,
    Retr(i64),
    Dele(i64),
    Noop,
    Rset,
    Quit,
}

impl std::fmt::Display for PopCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use PopCommand::*;
        match self {
            Greet => write!(f, "GREET"),
            User(s) => write!(f, "USER {}", s),
            Pass(s) => write!(f, "PASS {}", s),
            Stat => write!(f, "STAT"),
            UidlAll => write!(f, "UIDLALL"),
            UidlOne => write!(f, "UIDLONE"),
            ListAll => write!(f, "LISTALL"),
            ListOne => write!(f, "LISTONE"),
            Retr(i) => write!(f, "RETR {}", i),
            Dele(i) => write!(f, "DELE {}", i),
            Noop => write!(f, "NOOP"),
            Rset => write!(f, "RSET"),
            Quit => write!(f, "QUIT"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_test_account::{test_account_info, AccountAndServiceInfo};
    use regex::Regex;
    use rustls::{ClientConfig, ClientSession};
    use std::sync::Arc;
    use untrusted::Input as UIN;
    use webpki::DNSNameRef;

    #[test]
    fn it_works() {
        let AccountAndServiceInfo {
            account,
            smtp,
            imap,
            pop3,
            web,
        } = test_account_info().expect(womp!());
        drop((smtp, imap));
        let popinfo = pop3.expect(womp!());
        let webinfo = web.expect(womp!());
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let dn = capture!(r"http[s]{0,1}://(?P<name>[a-z]+\.[a-z]+)", &webinfo.uri)
            .name("name")
            .expect(womp!())
            .as_str();
        let session = ClientSession::new(
            &Arc::new(config),
            DNSNameRef::try_from_ascii(UIN::from(dn.as_bytes())).expect(womp!()),
        );
        let mut pop = PopStream::connect((popinfo.host.deref(), popinfo.port), session);
        assert!(dbg!(pop.user(&account.username)).success);
        assert!(dbg!(pop.pass(&account.password)).success);
        assert!(dbg!(pop.list_all()).is_ok());
        assert!(dbg!(pop.quit()).success);
    }
}
