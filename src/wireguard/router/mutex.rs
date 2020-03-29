/*
use std::sync::Mutex as StdMutex;
use std::sync::MutexGuard;

use std::sync::RwLock as StdRwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;

pub struct Mutex<T> {
    mutex: StdMutex<T>,
}

pub struct RwLock<T> {
    rwlock: StdRwLock<T>,
}

impl<T> Mutex<T> {
    pub fn new(v: T) -> Mutex<T> {
        Mutex {
            mutex: StdMutex::new(v),
        }
    }

    pub fn lock(&self) -> MutexGuard<T> {
        self.mutex.lock().unwrap()
    }
}

impl<T> RwLock<T> {
    pub fn new(v: T) -> RwLock<T> {
        RwLock {
            rwlock: StdRwLock::new(v),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<T> {
        self.rwlock.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.rwlock.write().unwrap()
    }
}
*/

use spin::Mutex as StdMutex;
use spin::MutexGuard;

use spin::RwLock as StdRwLock;
use spin::RwLockReadGuard;
use spin::RwLockWriteGuard;

pub struct Mutex<T> {
    mutex: StdMutex<T>,
}

pub struct RwLock<T> {
    rwlock: StdRwLock<T>,
}

impl<T> Mutex<T> {
    pub fn new(v: T) -> Mutex<T> {
        Mutex {
            mutex: StdMutex::new(v),
        }
    }

    pub fn lock(&self) -> MutexGuard<T> {
        self.mutex.lock()
    }

    pub fn try_lock(&self) -> Option<MutexGuard<T>> {
        self.mutex.try_lock()
    }
}

impl<T> RwLock<T> {
    pub fn new(v: T) -> RwLock<T> {
        RwLock {
            rwlock: StdRwLock::new(v),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<T> {
        self.rwlock.read()
    }

    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.rwlock.write()
    }
}
