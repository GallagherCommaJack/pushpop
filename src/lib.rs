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
        PopStream {
            is_authenticated: false,
            stream:           owned,
        }
    }

    pub fn stat(&mut self) -> Result<Stat, String> {
        write!(self.stream, "STAT").expect(womp!());
        let resp = self.read_response_line();
        resp_code!(resp);
        let captures = capture!(r"+OK (?P<msgs>[\d]+) (?P<oct>[\d]+)", &resp.first_line);
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
        write!(self.stream, "LIST").expect(womp!());
        let resp = self.read_response_line();
        resp_code!(resp);
        let captures = capture!(
            r"(?P<count>[\d]+) message[s]{0,1} \((?P<octs>[\d]+) [A-Za-z]*\)",
            &resp.first_line
        );
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
        write!(self.stream, "LIST {}", id).expect(womp!());
        let resp = self.read_response_line();
        resp_code!(resp);
        let captures = capture!(r"(?P<id>[\d]+) (?P<oct>[\d]+)", &resp.first_line);
        Ok(Scan {
            id:     parse_match!(captures, "id"),
            octets: parse_match!(captures, "oct"),
        })
    }

    pub fn retr(&mut self, id: u64) -> Result<Vec<String>, String> {
        write!(self.stream, "RETR {}", id).expect(womp!());
        let resp = self.read_response_to_end();
        resp_code!(resp);
        Ok(resp.lines)
    }

    pub fn dele(&mut self, id: u64) -> PopResponse {
        write!(self.stream, "DELE {}", id).expect(womp!());
        self.read_response_line()
    }

    pub fn noop(&mut self) -> PopResponse {
        write!(self.stream, "NOOP").expect(womp!());
        self.read_response_line()
    }

    pub fn rset(&mut self) -> PopResponse {
        write!(self.stream, "RSET").expect(womp!());
        self.read_response_line()
    }

    pub fn quit(&mut self) -> PopResponse {
        write!(self.stream, "QUIT").expect(womp!());
        self.read_response_line()
    }

    pub fn login(&mut self, user: &str, pass: &str) -> (PopResponse, PopResponse) {
        write!(self.stream, "USER {}", user).expect(womp!());
        let resp1 = self.read_response_line();
        write!(self.stream, "PASS {}", pass).expect(womp!());
        let resp2 = self.read_response_line();
        if resp1.success && resp2.success {
            self.is_authenticated = true;
        }
        (resp1, resp2)
    }

    fn read_ok_err(&mut self) -> bool {
        let mut buf = vec![0];
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
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
