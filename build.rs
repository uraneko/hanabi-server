use hanabi_build::{
    Error,
    db::{Database, DbPipeline, Table, TableLayout, TableOptions},
    dirs::Dir,
    ui::UiPipeline,
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
    let cargo_dir = Dir::new()?;
    let mut data_dir = cargo_dir.clone();
    data_dir.push(DATA_PATH);

    let users = USERS_TABLE.clone()?;
    let tokens = TOKENS_TABLE.clone()?;
    let main_db = Database::with_tables(MAIN_DB, [users, tokens]);
    let db = DbPipeline::with_dbs(data_dir, main_db);
    db.build()?;

    let js_dir = Dir::from_path("../../js/hanabi/");
    js_dir.goto()?;
    let ui = UiPipeline::new()
        .build(&["pnpm", "build"])
        .copy(["build", cargo_dir.as_str().unwrap()]);
    ui.update()?;
    cargo_dir.goto()?;

    Ok(())
}
