mod get;
mod set;

use std::io::{Read, Write};

use super::{ConfigError, Configuration};

const MAX_LINE_LENGTH: usize = 128;

struct Parser<C: Configuration, R: Read, W: Write> {
    config: C,
    reader: R,
    writer: W,
}

impl<C: Configuration, R: Read, W: Write> Parser<C, R, W> {
    fn new(&self, reader: R, writer: W, config: C) -> Parser<C, R, W> {
        Parser {
            config,
            reader,
            writer,
        }
    }

    fn parse(&mut self) -> Option<()> {
        // read string up to maximum length (why is this not in std?)
        let mut line = || {
            let mut m: [u8; 1] = [0u8];
            let mut l: String = String::with_capacity(MAX_LINE_LENGTH);
            while let Ok(_) = self.reader.read_exact(&mut m) {
                let c = m[0] as char;
                if c == '\n' {
                    return Some(l);
                };
                l.push(c);
                if l.len() > MAX_LINE_LENGTH {
                    break;
                }
            }
            None
        };

        match line()?.as_str() {
            "get=1" => Some(()),
            "set=1" => Some(()),
            _ => None,
        }
    }
}
