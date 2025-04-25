#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[cfg(test)]
        {
            if std::env::var("JOURNALER_DEBUG").ok().as_deref() == Some("1") {
                println!($($arg)*);
            }
        }
        #[cfg(not(test))]
        {
            if $crate::DEBUG_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                println!($($arg)*);
            }
        }
    };
}
