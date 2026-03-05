use serde::Deserialize;
use std::sync::LazyLock;

fn main() -> Result<(), Error> {
    let configs: Configs = CONFIGS.clone()?;
    println!("{:#?}", configs);

    Ok(())
}

const CONFIGS: LazyLock<Result<Configs, Error>> = LazyLock::new(|| {
    let data = std::fs::read_to_string("config.ini").map_err(|_| Error::FailedToReadConfigs)?;

    serde_ini::from_str(&data).map_err(|_| Error::FailedToParseConfigs)
});

#[derive(Debug, Clone)]
enum Error {
    FailedToReadConfigs,
    FailedToParseConfigs,
}

impl From<&Error> for Error {
    fn from(err: &Error) -> Error {
        err.clone()
    }
}

#[derive(Debug, Deserialize, Clone)]
struct Configs {
    main: Main,
    plugins: Vec<Plugin>,
}

#[derive(Debug, Deserialize, Clone)]
struct Main {
    plugins: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Plugin {
    addr: String,
    tags: Vec<String>,
    color: String,
}
