use core::iter::Peekable;
use hanabi_configs::configs::Configs;
use hanabi_configs::parse::{AnalyzeSemantics, AnalyzeSyntax, Error, Lex, Parse, parse_vec};
use hanabi_configs::parse::{Attribute, Component, Property, Section};
use std::collections::HashMap;

fn main() -> Result<(), &'static str> {
    let configs = std::fs::read("config.ini").map_err(|_| "file probably not there")?;
    println!("{:?}", str::from_utf8(&configs));
    let configs = Configs::deserialize(&configs).map_err(|err| {
        println!("{:?}", err);

        "parse error"
    })?;
    println!("{:#?}", configs);

    Ok(())
}
