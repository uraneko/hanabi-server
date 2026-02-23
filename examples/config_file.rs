use core::iter::Peekable;
use hanabi_configs::{AnalyzeSemantics, AnalyzeSyntax, Error, Lex, Parse, parse_vec};
use hanabi_configs::{Attribute, Component, Property, Section};
use std::collections::HashMap;

fn main() -> Result<(), &'static str> {
    let configs = std::fs::read("config.ini").map_err(|_| "file probably not there")?;
    println!("{:?}", str::from_utf8(&configs));
    let configs = Configs::deserialize(&configs).map_err(|err| {
        println!("{:?}", err);

        "parse error"
    })?;
    println!("{:?}", configs);

    Ok(())
}

#[derive(Debug, Default)]
struct Configs {
    main: Main,
    plugins: HashMap<&'static str, Plugin>,
}

#[derive(Debug, Default)]
struct Main {
    plugins: Vec<String>,
}

#[derive(Debug, Default)]
struct Plugin {
    disabled: bool,
    addr: String,
    tags: Vec<String>,
    color: String,
}

impl Parse for Configs {
    fn parse_section(
        &mut self,
        section: Vec<String>,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        match section.as_slice() {
            [val] if val == "main" => self.parse_main(iter)?,
            [root, branch] if root == "plugins" && branch == "drive" => self.parse_drive(iter)?,
            _ => return Err(Error::UnrecognizableSection),
        }

        Ok(())
    }
}

impl Configs {
    fn parse_main(
        &mut self,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        loop {
            let Some(peeked) = iter.peek() else {
                return Ok(());
            };
            if peeked.is_section() {
                return Ok(());
            }

            let Some(comp) = iter.next() else {
                unreachable!("just checked that out above")
            };
            self.parse_main_comp(comp)?;
        }
    }

    fn parse_main_comp(&mut self, comp: Component) -> Result<(), Error> {
        match comp {
            Component::Comment(_) => return Ok(()),
            Component::Property(Property { key, val }) => {
                if key != "plugins" {
                    return Err(Error::UndesirablePropertyKey);
                }
                self.main.plugins = parse_vec(&val)?;
            }
            _ => return Err(Error::UnexpectedComponent),
        }

        Ok(())
    }

    fn parse_drive(
        &mut self,
        iter: &mut Peekable<impl Iterator<Item = Component>>,
    ) -> Result<(), Error> {
        let mut drive = Plugin::default();
        loop {
            let Some(peeked) = iter.peek() else {
                break;
            };
            if peeked.is_section() {
                return Ok(());
            }

            let Some(comp) = iter.next() else {
                unreachable!("just checked that out above")
            };

            self.parse_drive_comp(comp, &mut drive)?;
        }
        self.plugins.insert("drive", drive);

        Ok(())
    }

    fn parse_drive_comp(&mut self, comp: Component, drive: &mut Plugin) -> Result<(), Error> {
        match comp {
            Component::Comment(_) => return Ok(()),
            Component::Property(Property { key, val }) => match key.as_str() {
                "addr" => {
                    println!("::: {}", val);
                    drive.addr = val
                }
                "tags" => drive.tags = parse_vec(&val)?,
                "color" => drive.color = val,
                _ => return Err(Error::UndesirablePropertyKey),
            },
            Component::Attribute(Attribute(attr)) => {
                if attr != "disabled" {
                    return Err(Error::UnexpectedAttribute);
                }
                drive.disabled = true;
            }
            _ => return Err(Error::UnexpectedComponent),
        }
        println!("==={:?}", drive);

        Ok(())
    }
}
