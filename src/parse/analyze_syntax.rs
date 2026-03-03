use super::lex::Token;

#[derive(Debug, PartialEq, Eq)]
pub enum TokenGroup {
    Section(Vec<Token>),
    Comment(Token),
    Property([Token; 2]),
    Attribute(Token),
}

#[derive(Debug)]
pub enum Error {
    UnparsableTokenCombination,
    ExpectedEogFoundToken,
    ExpectedEqualsToken,
    SectionIsEmpty,
}

pub struct AnalyzeSyntax {
    tokens: Vec<Token>,
}

impl AnalyzeSyntax {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens }
    }

    pub fn analyze(mut self) -> Result<Vec<TokenGroup>, Error> {
        let mut groups = vec![];
        // let eol_suffix = self.tokens[self.tokens.len() - 1].is_eol()
        // ends of lines

        while let Some(idx) = find_eol(&self.tokens) {
            // + 1 cuz we dont want the eol token to mess up the next iteration, if any
            println!("-><{:?}", &self.tokens[..idx + 1]);
            let mut iter = self.tokens.drain(..idx + 1);
            // this gets rid of eol token
            iter.next_back();
            groups.push(group_tokens(iter)?);

            if self.tokens.is_empty() {
                return Ok(groups);
            }
        }

        let last_group = group_tokens(self.tokens.into_iter())?;
        groups.push(last_group);

        Ok(groups)
    }
}

fn find_eol(tokens: &[Token]) -> Option<usize> {
    println!("***{:?}", tokens);
    let mut idx = 0;
    let last = tokens.len() - 1;
    loop {
        if tokens[idx].is_eol() {
            return Some(idx);
        } else if idx == last {
            return None;
        }
        idx += 1;
    }
}

fn group_tokens(mut iter: impl DoubleEndedIterator<Item = Token>) -> Result<TokenGroup, Error> {
    // pop the eol token
    match [iter.next(), iter.next_back()] {
        [Some(Token::LeftBracket), Some(Token::RightBracket)] => group_section(iter),
        [Some(Token::Pound), Some(comment_token @ Token::Sequence(_))] => {
            group_comment(comment_token, iter)
        }
        [
            Some(key_token @ Token::Sequence(_)),
            Some(val_token @ Token::Sequence(_)),
        ] => group_property(key_token, val_token, iter),
        [Some(attr_token @ Token::Sequence(_)), None] => group_attribute(attr_token, iter),
        erroneous => {
            println!("{:?}", erroneous);
            Err(Error::UnparsableTokenCombination)
        }
    }
}

fn group_section(iter: impl DoubleEndedIterator<Item = Token>) -> Result<TokenGroup, Error> {
    let tokens: Vec<Token> = iter.collect();
    if tokens.is_empty() {
        return Err(Error::SectionIsEmpty);
    }

    Ok(TokenGroup::Section(tokens))
}

fn group_comment(
    comment: Token,
    mut iter: impl DoubleEndedIterator<Item = Token>,
) -> Result<TokenGroup, Error> {
    if let Some(_) = iter.next() {
        return Err(Error::ExpectedEogFoundToken);
    }

    Ok(TokenGroup::Comment(comment))
}

fn group_property(
    key: Token,
    val: Token,
    mut iter: impl DoubleEndedIterator<Item = Token>,
) -> Result<TokenGroup, Error> {
    let Some(Token::Equals) = iter.next() else {
        return Err(Error::ExpectedEqualsToken);
    };

    Ok(TokenGroup::Property([key, val]))
}

fn group_attribute(
    attr: Token,
    mut iter: impl DoubleEndedIterator<Item = Token>,
) -> Result<TokenGroup, Error> {
    if let Some(_) = iter.next() {
        return Err(Error::ExpectedEogFoundToken);
    }

    Ok(TokenGroup::Attribute(attr))
}
