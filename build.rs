use hanabi_build::{
    Error,
    db::{DBPipeline, DataDir, Database, Table, TableLayout, TableOptions},
    ui::UIPipeline,
};
use std::sync::LazyLock;

const DATA_PATH: &str = "data";
const MAIN_DB: &str = concat!("data", "/", "main.db3");
const USERS_TABLE: LazyLock<Result<Table, Error>> = LazyLock::new(|| {
    let mut opts = TableOptions::new();
    opts.make(true).check(true).remake(false);
    let layout = TableLayout::with_columns([
        ("name", "text|nn|pk".parse()?),
        ("email", "blob|u".parse()?),
        ("pswd", "blob|nn|u".parse()?),
        ("salt", "text|nn|u".parse()?),
        ("created", "int|nn".parse()?),
    ]);

    Ok(Table::new("users", layout, opts))
});

const TOKENS_TABLE: LazyLock<Result<Table, Error>> = LazyLock::new(|| {
    let mut opts = TableOptions::new();
    opts.make(true).check(true).remake(false);
    let layout = TableLayout::with_columns([
        ("name", "text|nn|pk".parse()?),
        ("refresh", "blob|u".parse()?),
        ("access", "blob|u".parse()?),
    ]);

    Ok(Table::new("tokens", layout, opts))
});

fn main() -> Result<(), Error> {
    println!("cargo:rerun-if-changed=../../js/hanabi/hanabi*/src");
    let ddir = DataDir::new(DATA_PATH);
    let users = USERS_TABLE.clone()?;
    let tokens = TOKENS_TABLE.clone()?;

    let main_db = Database::with_tables(MAIN_DB, [users, tokens]);
    let pipeline = DBPipeline::with_dbs(ddir, main_db);
    pipeline.build()?;

    let pipeline = UIPipeline::new().copy(true).build(false);
    pipeline.update("../../js/hanabi/hanabi", "build")?;

    Ok(())
}
