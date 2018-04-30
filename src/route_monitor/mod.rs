#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::linux::RouteListener;