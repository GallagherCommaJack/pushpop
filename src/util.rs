#[macro_export]
macro_rules! womp {
    () => {
        &format!("{}:{}:{}", file!(), line!(), column!())
    };
    ($message:expr) => {
        &format!("{}:{}:{} {}", file!(), line!(), column!(), $message)
    };
}

#[macro_export]
macro_rules! regex {
    ($r:expr) => {
        Regex::new($r).expect(womp!())
    };
}

#[macro_export]
macro_rules! capture {
    ($r:expr, $e:expr) => {
        regex!($r).captures($e).expect(womp!())
    };
}

#[macro_export]
macro_rules! resp_code {
    ($r:ident) => {
        if !$r.success {
            return Err($r.first_line);
        }
    };
}

#[macro_export]
macro_rules! parse_match {
    ($e:expr, $i:expr) => {
        $e.name($i).expect(womp!()).as_str().parse().expect(womp!())
    };
}
