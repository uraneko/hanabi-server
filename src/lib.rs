use core::iter::Peekable;

mod analyze_semantics;
mod analyze_syntax;
mod lex;

pub use analyze_semantics::AnalyzeSemantics;
pub use analyze_syntax::AnalyzeSyntax;
pub use lex::Lex;

pub use analyze_semantics::{
    Attribute, Comment, Component, Error as SemanticsError, Property, Section,
};
use analyze_syntax::Error as SyntaxError;
use lex::Error as LexError;

#[derive(Debug)]
pub enum Error {
    Lex(LexError),
    Syntax(SyntaxError),
    Semantics(SemanticsError),
    ExpectedMainSection,
    InputIsEmpty,
    UnexpectedPropertyKey,
    UnexpectedComponent,
    UnexpectedAttribute,
    FailedToParseValue,
    UnrecognizableSection,
}

pub trait Parse: Sized {
    fn deserialize(input: &[u8]) -> Result<Self, Error>;

    fn parse_section(
        &mut self,
        section: Vec<String>,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error>;
}

pub fn parse_vec(s: &str) -> Result<Vec<String>, Error> {
    let v: Vec<String> = s.split(' ').map(|s| s.into()).collect();
    if v.is_empty() {
        return Err(Error::FailedToParseValue);
    }

    Ok(v)
}

macro_rules! convert_err {
    ($err_ty: ty, $err_var: ident) => {
        impl From<$err_ty> for Error {
            fn from(err: $err_ty) -> Self {
                Self::$err_var(err)
            }
        }
    };
}

convert_err!(LexError, Lex);
convert_err!(SyntaxError, Syntax);
convert_err!(SemanticsError, Semantics);
