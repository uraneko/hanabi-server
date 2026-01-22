use rusqlite::Connection;
use std::env::set_current_dir as cd;
use std::process::{Command as Cmd, ExitStatus};
use std::{fs, path::Path};

#[derive(Debug)]
enum Error {
    DB(DBErr),
    UI(UIErr),
}

impl From<DBErr> for Error {
    fn from(err: DBErr) -> Self {
        Self::DB(err)
    }
}

impl From<UIErr> for Error {
    fn from(err: UIErr) -> Self {
        Self::UI(err)
    }
}

fn main() -> Result<(), Error> {
    println!("cargo:rerun-if-changed=../../js/hanabi/hanabi*/src");
    check_db()?;
    update_ui()?;

    Ok(())
}

fn update_ui() -> Result<(), UIErr> {
    change_dir()?;
    build_ui()?;

    copy_ui().map(|_| ())
}

#[derive(Debug)]
enum UIErr {
    FailedToChangeDir,
    FailedToBuildPnpmPackage,
    FailedToCopyFiles,
}

fn change_dir() -> Result<(), UIErr> {
    cd("../../js/hanabi/hanabi").map_err(|_| UIErr::FailedToChangeDir)
}

fn build_ui() -> Result<ExitStatus, UIErr> {
    Cmd::new("pnpm")
        .arg("build")
        .status()
        .map_err(|_| UIErr::FailedToBuildPnpmPackage)
}

fn copy_ui() -> Result<ExitStatus, UIErr> {
    Cmd::new("cp")
        .args(&["build", "-r", "../../../rust/hanabi"])
        .status()
        .map_err(|_| UIErr::FailedToCopyFiles)
}

fn check_db() -> Result<(), DBErr> {
    match check_dir() {
        Err(DBErr::DataIsNotADir) => panic!("data already exists and is not a dir"),
        Err(DBErr::DataDirNotFound) => make_dir()?,
        Ok(()) => (),
        _ => unreachable!("function doesnt return this variant"),
    }
    let conn = open_database()?;
    match check_table(&conn) {
        Ok(()) => (),
        Err(DBErr::FailedToProcessQueryRow) => {
            panic!("internal error; db query processing failed")
        }
        Err(DBErr::TableNotFound) => make_table(&conn)?,
        _ => unreachable!("function doesnt return this variant"),
    }

    check_columns(&conn)
}

#[derive(Debug)]
enum DBErr {
    FailedToCreateDataDir,
    FailedToOpenDB,
    FailedToProcessQueryRow,
    TableNotFound,
    TableCreateFailed,
    TableColumnsMismatch,
    DataDirNotFound,
    DataIsNotADir,
}

fn check_dir() -> Result<(), DBErr> {
    let path = Path::new("data");
    if path.is_file() || path.is_symlink() {
        return Err(DBErr::DataIsNotADir);
    } else if !path.exists() {
        return Err(DBErr::DataDirNotFound);
    }

    Ok(())
}

fn make_dir() -> Result<(), DBErr> {
    fs::create_dir("data").map_err(|_| DBErr::FailedToCreateDataDir)
}

// creates a new db if it doesnt exist
fn open_database() -> Result<Connection, DBErr> {
    Connection::open("data/main.db3").map_err(|_| DBErr::FailedToOpenDB)
}

fn check_table(conn: &Connection) -> Result<(), DBErr> {
    let table_name: String = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users';",
            [],
            |row| row.get(0),
        )
        .map_err(|_| DBErr::FailedToProcessQueryRow)?;

    if table_name.as_str() != "users" {
        return Err(DBErr::TableNotFound);
    }

    Ok(())
}

fn make_table(conn: &Connection) -> Result<(), DBErr> {
    conn.execute(
        "create table users (name text not null primary key, email blob unique, pswd blob not null unique, salt text not null unique, created integer not null) strict;", []
    )
    .map_err(|_| DBErr::TableCreateFailed).map(|_| ())
}

const COLS: &[&str] = &["name", "email", "pswd", "salt", "created"];

fn check_columns(conn: &Connection) -> Result<(), DBErr> {
    if !conn
        .prepare("select * from users limit 0")
        .map(|stt| stt.column_names() == COLS)
        .map_err(|_| DBErr::FailedToProcessQueryRow)?
    {
        return Err(DBErr::TableColumnsMismatch);
    }

    Ok(())
}
