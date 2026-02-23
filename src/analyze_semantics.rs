use super::analyze_syntax::TokenGroup;
use super::lex::Token;

#[derive(Debug)]
pub enum Component {
    Section(Section),
    Comment(Comment),
    Property(Property),
    Attribute(Attribute),
}

#[derive(Debug)]
pub struct Section(Vec<String>);

#[derive(Debug)]
pub struct Comment(String);

#[derive(Debug)]
pub struct Property {
    key: String,
    // val is converted into a useful type value at parse time
    val: String,
}

#[derive(Debug)]
pub struct Attribute(String);

#[derive(Debug)]
pub struct AnalyzeSemantics {
    groups: Vec<TokenGroup>,
}

#[derive(Debug)]
pub enum Error {
    ExpectedSequence,
    ExpectedDot,
}

impl AnalyzeSemantics {
    pub fn new(groups: Vec<TokenGroup>) -> Self {
        Self { groups }
    }

    pub fn analyze(mut self) -> Result<Vec<Component>, Error> {
        let mut components = vec![];
        let main_section = force_main_section(&mut self.groups);
        components.push(main_section);
        let mut iter = self.groups.into_iter();
        while let Some(group) = iter.next() {
            components.push(collect_component_from_group(group)?);
        }

        Ok(components)
    }
}

// a main section MUST exist as the first token group
// if not then 1 is prepended here
fn force_main_section(groups: &mut Vec<TokenGroup>) -> Component {
    if let Some(TokenGroup::Section(section)) = groups.first()
        && *section == vec![Token::Sequence("main".into())]
    {
        groups.remove(0);
    }
    Component::Section(Section(vec!["main".into()]))
}

fn collect_component_from_group(group: TokenGroup) -> Result<Component, Error> {
    match group {
        TokenGroup::Section(section) => collect_section(section),
        TokenGroup::Comment(comment) => collect_comment(comment),
        TokenGroup::Property(prop) => collect_property(prop),
        TokenGroup::Attribute(attr) => collect_attribute(attr),
    }
}

fn collect_section(section: Vec<Token>) -> Result<Component, Error> {
    let mut nodes = vec![];
    let mut iter = section.into_iter();
    while let Some(token) = iter.next() {
        let Token::Sequence(seq) = token else {
            return Err(Error::ExpectedSequence);
        };
        nodes.push(seq);

        match iter.next() {
            None => return Ok(Component::Section(Section(nodes))),
            Some(Token::Dot) => continue,
            _ => return Err(Error::ExpectedDot),
        }
    }

    Ok(Component::Section(Section(nodes)))
}

fn collect_comment(comment: Token) -> Result<Component, Error> {
    let Token::Sequence(cmnt) = comment else {
        return Err(Error::ExpectedSequence);
    };

    Ok(Component::Comment(Comment(cmnt)))
}

fn collect_property(prop: [Token; 2]) -> Result<Component, Error> {
    let [Token::Sequence(key), Token::Sequence(val)] = prop else {
        return Err(Error::ExpectedSequence);
    };

    Ok(Component::Property(Property { key, val }))
}

fn collect_attribute(attr: Token) -> Result<Component, Error> {
    let Token::Sequence(attr) = attr else {
        return Err(Error::ExpectedSequence);
    };

    Ok(Component::Attribute(Attribute(attr)))
}
