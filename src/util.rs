#[macro_export]
macro_rules! womp {
    () => {
        &format!("{}:{}:{}", file!(), line!(), column!())
    };
    ($message:expr) => {
        &format!("{}:{}:{} {}", file!(), line!(), column!(), $message)
    };
}
