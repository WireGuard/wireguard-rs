use std::{io, os::unix::io::RawFd, sync::Arc};

struct FdInner {
    fd: RawFd,
}

impl Drop for FdInner {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

#[derive(Clone)]
pub(super) struct Fd {
    fd: Arc<FdInner>,
}

impl Fd {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd: Arc::new(FdInner { fd }),
        }
    }

    pub unsafe fn raw_fd(&self) -> RawFd {
        self.fd.fd
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let bytes_read = unsafe { libc::write(self.raw_fd(), buf.as_ptr() as _, buf.len()) };
        if bytes_read < 0 {
            return Err(io::Error::from_raw_os_error(-bytes_read as i32));
        }
        Ok(bytes_read as usize)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_written = unsafe { libc::read(self.raw_fd(), buf.as_mut_ptr() as _, buf.len()) };
        if bytes_written < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes_written as usize)
    }
}
