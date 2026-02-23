use core::iter::Peekable;
use hanabi_configs::{AnalyzeSemantics, AnalyzeSyntax, Error, Lex, Parse, parse_vec};
use hanabi_configs::{Attribute, Component, Property, Section};

const INPUT: &[u8; 67] =
    b"logging\nverbosity=warn\n[apps]\n\rinstalled=drive comms machines\n[abc]";
fn main() {
    // let mut lex = Lex::new(INPUT);
    // let tokens = lex.lex();
    // println!("{:?}", tokens);
    //
    // let analyze = AnalyzeSyntax::new(tokens.unwrap());
    // let groups = analyze.analyze();
    // println!("{:?}", groups);
    //
    // let analyze = AnalyzeSemantics::new(groups.unwrap());
    // let components = analyze.analyze();
    // println!("{:?}", components);

    let parsed = Test::deserialize(INPUT);
    println!("{:?}", parsed);
}

#[derive(Debug, Default)]
struct Test {
    logging: bool,
    verbosity: String,
    abc: Abc,
    apps: Apps,
}

#[derive(Debug, Default)]
struct Abc;

#[derive(Debug, Default)]
struct Apps {
    installed: Vec<String>,
}

impl Parse for Test {
    fn deserialize(slice: &[u8]) -> Result<Self, Error> {
        let tokens = Lex::new(slice).lex()?;
        let groups = AnalyzeSyntax::new(tokens).analyze()?;
        let components = AnalyzeSemantics::new(groups).analyze()?;
        if components.is_empty() {
            return Err(Error::InputIsEmpty);
        }

        let mut iter = components.into_iter().peekable();
        // // ignore main section component
        // // we already know it exists since we forced it in the semantic analysis
        // iter.next();

        let mut test = Test::default();
        while let Some(Component::Section(Section(section))) = iter.next() {
            test.parse_section(section, &mut iter)?;
        }

        Ok(test)
    }

    fn parse_section(
        &mut self,
        section: Vec<String>,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        let parser = match section.as_slice() {
            [val] if val == "main" => Self::parse_main,
            [val] if val == "apps" => Self::parse_apps,
            [val] if val == "abc" => Self::parse_abc,
            _ => return Err(Error::UnrecognizableSection),
        };
        loop {
            let Some(peeked) = iter.peek() else {
                return Ok(());
            };
            if peeked.is_section() {
                return Ok(());
            }

            parser(self, iter)?;
        }
        // match section.as_slice() {
        //     [val] if val == "main" => self.parse_main(iter)?,
        //     _ => todo!(),
        // }
        // Ok(())
    }
}

impl Test {
    fn parse_main(
        &mut self,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        for _ in 0..2 {
            match iter.next() {
                Some(Component::Property(Property { key, val })) => {
                    if key != "verbosity" {
                        return Err(Error::UnexpectedPropertyKey);
                    }

                    self.verbosity = val;
                }
                Some(Component::Attribute(Attribute(attr))) => {
                    if attr != "logging" {
                        return Err(Error::UnexpectedAttribute);
                    }
                    self.logging = true;
                }
                None => unreachable!("None was handled by peekable before getting here"),
                _ => return Err(Error::UnexpectedComponent),
            }
        }

        Ok(())
    }

    fn parse_apps(
        &mut self,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        match iter.next() {
            Some(Component::Property(Property { key, val })) => {
                if key != "installed" {
                    return Err(Error::UnexpectedPropertyKey);
                }
                self.apps.installed = parse_vec(&val)?;
            }
            None => unreachable!("None was handled by peekable before getting here"),
            _ => return Err(Error::UnexpectedComponent),
        }
        Ok(())
    }

    fn parse_abc(
        &mut self,
        _iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
