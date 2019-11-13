mod get;
mod set;

use std::io::{Read, Write};

use super::{ConfigError, Configuration};

use get::serialize;
use set::LineParser;

const MAX_LINE_LENGTH: usize = 256;

pub fn process<R: Read, W: Write, C: Configuration>(reader: &mut R, writer: &mut W, config: &C) {
    fn operation<R: Read, W: Write, C: Configuration>(
        reader: &mut R,
        writer: &mut W,
        config: &C,
    ) -> Result<(), ConfigError> {
        // read string up to maximum length (why is this not in std?)
        fn readline<R: Read>(reader: &mut R) -> Result<String, ConfigError> {
            let mut m: [u8; 1] = [0u8];
            let mut l: String = String::with_capacity(MAX_LINE_LENGTH);
            while let Ok(_) = reader.read_exact(&mut m) {
                let c = m[0] as char;
                if c == '\n' {
                    return Ok(l);
                };
                l.push(c);
                if l.len() > MAX_LINE_LENGTH {
                    return Err(ConfigError::LineTooLong);
                }
            }
            return Err(ConfigError::IOError);
        }

        // split into (key, value) pair
        fn keypair<'a>(ln: &'a str) -> Result<(&'a str, &'a str), ConfigError> {
            let mut split = ln.splitn(2, "=");
            match (split.next(), split.next()) {
                (Some(key), Some(value)) => Ok((key, value)),
                _ => Err(ConfigError::LineTooLong),
            }
        };

        // read operation line
        match readline(reader)?.as_str() {
            "get=1" => serialize(writer, config).map_err(|_| ConfigError::IOError),
            "set=1" => {
                let mut parser = LineParser::new(config);
                loop {
                    let ln = readline(reader)?;
                    if ln == "" {
                        break Ok(());
                    };
                    let (k, v) = keypair(ln.as_str())?;
                    parser.parse_line(k, v)?;
                }
            }
            _ => Err(ConfigError::InvalidOperation),
        }
    }

    // process operation
    let res = operation(reader, writer, config);
    log::debug!("{:?}", res);

    // return errno
    let _ = writer.write("errno=".as_ref());
    let _ = writer.write(
        match res {
            Err(e) => e.errno().to_string(),
            Ok(()) => "0".to_owned(),
        }
        .as_ref(),
    );
    let _ = writer.write("\n\n".as_ref());
}
