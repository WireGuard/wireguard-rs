/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

use failure::Error;
use futures::{self, Future, Async, Poll, Stream};
use notify::{self, Watcher, RecursiveMode, RawEvent, raw_watcher};
use std::{self, thread, time::Duration, path::Path};
use tokio_core::reactor::Handle;
use tokio_signal::{self, unix::{Signal, SIGTERM}};

pub struct GrimReaper {
    rx: futures::sync::oneshot::Receiver<()>,
    signal: Box<Stream<Item = (), Error = std::io::Error>>,
}

impl GrimReaper {
    pub fn spawn(handle: &Handle, socket_path: &Path) -> Result<Self, Error> {
        let (std_tx, std_rx) = std::sync::mpsc::channel::<RawEvent>();
        let (tx,     rx    ) = futures::sync::oneshot::channel::<()>();

        let path = socket_path.to_owned();
        debug!("grim reaper spawning for {}.", socket_path.to_string_lossy());

        thread::Builder::new()
            .name("grim reaper".into())
            .spawn(move || {
                thread::sleep(Duration::from_millis(500)); // TODO we shouldn't need this.
                let mut watcher = raw_watcher(std_tx).unwrap();
                watcher.watch(path, RecursiveMode::Recursive).unwrap();

                loop {
                    debug!("listening");
                    let event = std_rx.recv().unwrap();
                    debug!("FS EVENT: {:?}", event);
                    if event.op.unwrap() == notify::op::REMOVE {
                        tx.send(()).unwrap();
                        panic!("configuration socket removed, sounding death cry.")
                    }
                }
            })?;

        let sigint  = tokio_signal::ctrl_c(handle).flatten_stream();
        let sigterm = Signal::new(SIGTERM, handle).flatten_stream().map(|_| ());
        let signal  = Box::new(sigint.select(sigterm));

        Ok(Self { rx, signal })
    }
}

impl Future for GrimReaper {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.rx.poll() {
            Ok(Async::NotReady) => {},
            _ => {
                info!("configuration socket removed, bubbling up to reactor core.");
                return Err(())
            },
        }

        match self.signal.poll() {
            Ok(Async::NotReady) => {},
            _ => {
                info!("SIGINT received, bubbling up to reactor core.");
                return Err(())
            },
        }

        Ok(Async::NotReady)
    }
}
