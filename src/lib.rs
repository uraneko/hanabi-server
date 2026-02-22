#[derive(Debug)]
pub enum Token {
    Sequence(String),
    Equals,
    Dot,
    Pound,
    RightBracket,
    LeftBracket,
    LF,
    CRLF,
    LFCR,
}

impl Token {
    fn len(&self) -> usize {
        match self {
            Self::CRLF | Self::LFCR => 2,
            Self::Sequence(seq) => seq.len(),
            _ => 1,
        }
    }
}

macro_rules! tkn {
    ('[') => {
        Token::LeftBracket
    };
    (']') => {
        Token::RightBracket
    };
    (=) => {
        Token::Equals
    };
    (#) => {
        Token::Pound
    };
    (lf) => {
        Token::LF
    };
    (lfcr) => {
        Token::LFCR
    };
    (crlf) => {
        Token::CRLF
    };
    (.) => {
        Token::Dot
    };
    ($var: ident) => {
        Token::Sequence($var)
    };
    ($val: expr) => {
        Token::Sequence($val.into())
    };
}

#[derive(Debug)]
pub enum Error {
    LineIsNotAComment,
    TokenByteMismatch,
    TokenBytesMismatch,
    LineIsNotASection,
    InvalidINIEscapeSequence,
    ExpectedByteFoundEol,
    InvalidEscapeForComponent,
    UnparsableLine,
}

#[derive(Debug)]
pub struct Lex<'a> {
    slice: &'a [u8],
    cursor: usize,
    str_buf: String,
}

impl<'a> Lex<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self {
            slice,
            cursor: 0,
            str_buf: "".into(),
        }
    }

    pub fn lex(&mut self) -> Result<Vec<Token>, Error> {
        let mut tokens = vec![];
        while let Some((eol, eol_tkn)) = find_eol_idx(self.slice, self.cursor) {
            lex_line(
                &self.slice[self.cursor..eol],
                &mut tokens,
                &mut self.str_buf,
            )?;
            self.cursor = eol + eol_tkn.len();
            tokens.push(eol_tkn);
        }
        lex_line(&self.slice[self.cursor..], &mut tokens, &mut self.str_buf)?;

        Ok(tokens)
    }
}

fn find_eol_idx(buf: &[u8], cursor: usize) -> Option<(usize, Token)> {
    let slice = &buf[cursor..];
    let len = slice.len();
    let mut idx = 0;
    loop {
        if slice[idx] == 13 {
            // check if 10 follows, if it does return
            if idx == len - 1 {
                return None;
            } else if slice[idx + 1] == 10 {
                return Some((cursor + idx, tkn!(crlf)));
            }
        } else if slice[idx] == 10 {
            // check if 13 follows / return either way
            if idx == len - 1 {
                return Some((cursor + idx, tkn!(lf)));
            } else if slice[idx + 1] == 13 {
                return Some((cursor + idx, tkn!(lfcr)));
            } else {
                return Some((cursor + idx, tkn!(lf)));
            }
        } else if idx == slice.len() - 1 {
            return None;
        }

        idx += 1;
    }
}

fn lex_line(line: &[u8], tokens: &mut Vec<Token>, str_buf: &mut String) -> Result<(), Error> {
    str_buf.clear();
    let line = line.trim_ascii();
    match line {
        line if line_is_section(line) => lex_section(line, tokens, str_buf)?,
        line if line_is_comment(line) => lex_comment(line, tokens, str_buf)?,
        line if line_is_property(line) => lex_property(),
        line if line_is_attribute(line) => lex_attribute(),
        _ => return Err(Error::UnparsableLine),
    }

    Ok(())
}

fn bypass_space(slice: &[u8], cursor: &mut usize) {
    while slice[*cursor] == 32 {
        *cursor += 1;
    }
}

fn consume_line_spaces(line: &[u8]) -> [usize; 2] {
    let mut start = 0;
    while line[start] == 32 {
        start += 1;
    }
    let len = line.len() - 1;
    let mut end = 0;
    while line[len - end] == 32 {
        end += 1;
    }

    [start, end]
}

fn revert_escape_sequence(seq: &[u8]) -> Result<u8, Error> {
    Ok(match seq {
        b"\\." => b'.',
        b"\\#" => b'#',
        b"\\=" => b'=',
        b"\\]" => b']',
        b"\\\\" => b'\\',
        _ => return Err(Error::InvalidINIEscapeSequence),
    })
}

fn lex_section(line: &[u8], tokens: &mut Vec<Token>, str_buf: &mut String) -> Result<(), Error> {
    let len = line.len();
    if line[0] != b'[' || line[len - 1] != b']' {
        return Err(Error::LineIsNotASection);
    };
    tokens.push(tkn!('['));
    let mut iter = line[1..len - 1].iter();
    while let Some(byte) = iter.next() {
        match byte {
            // incoming escape, handle here, dont pass it to the while loop
            b'\\' => match iter.next() {
                Some(n @ b']') | Some(n @ b'.') => {
                    str_buf.push(*n as char);
                }
                None => return Err(Error::ExpectedByteFoundEol),
                _ => return Err(Error::InvalidEscapeForComponent),
            },
            // section partitioner
            b'.' => {
                tokens.push(tkn!(str_buf.drain(..).collect::<String>()));
                tokens.push(tkn!(.));
            }
            // normal byte/char, simply take it
            b => {
                str_buf.push(*b as char);
            }
        }
    }

    tokens.extend([tkn!(str_buf.clone()), tkn!(']')]);

    Ok(())
}
fn line_is_section(line: &[u8]) -> bool {
    line.starts_with(b"[") && line.ends_with(b"]")
}

fn lex_comment(line: &[u8], tokens: &mut Vec<Token>, str_buf: &mut String) -> Result<(), Error> {
    if line[0] != b'#' {
        return Err(Error::LineIsNotAComment);
    }
    str_buf.extend(line[1..].iter().map(|b| *b as char));
    tokens.extend([tkn!(#), tkn!(str_buf.clone())]);

    Ok(())
}
fn line_is_comment(line: &[u8]) -> bool {
    line.starts_with(b"#")
}

fn lex_property() {}
fn line_is_property(line: &[u8]) -> bool {
    line.contains(&b'=') && !line.starts_with(b"=") && !line.ends_with(b"=")
}

fn lex_attribute() {}
fn line_is_attribute(line: &[u8]) -> bool {
    line.iter()
        .enumerate()
        .filter_map(|(i, b)| if *b == b'=' { Some(i) } else { None })
        .map(|idx| idx > 0 && line[idx - 1] == b'\\')
        .any(|b| !b)
}
