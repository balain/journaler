#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        #[allow(unused_unsafe)]
        unsafe {
            #[cfg(test)]
            {
                if std::env::var("JOURNALER_DEBUG").ok().as_deref() == Some("1") {
                    println!($($arg)*);
                }
            }
            #[cfg(not(test))]
            {
                if DEBUG_ENABLED {
                    println!($($arg)*);
                }
            }
        }
    };
}
