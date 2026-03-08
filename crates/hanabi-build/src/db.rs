use rusqlite::{Connection, types::Type};
use std::collections::{HashMap, HashSet};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub enum Error {
    FailedToCreateDataDir,
    FailedToOpenDB,
    FailedToProcessQueryRow,
    TableNotFound,
    FailedToDropTable,
    TableCreateFailed,
    TableColumnsMismatch,
    DataDirNotFound,
    DataIsNotADir,
    InvalidConversionStr,
}

#[derive(Debug)]
pub struct DataDir(PathBuf);

impl DataDir {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self(PathBuf::from(path.as_ref()))
    }

    pub fn check(&self) -> Result<(), Error> {
        if !self.0.exists() {
            return Err(Error::DataDirNotFound);
        } else if !self.0.is_dir() {
            return Err(Error::DataIsNotADir);
        }

        Ok(())
    }

    pub fn make(&self) -> Result<(), Error> {
        fs::create_dir(&self.0).map_err(|_| Error::FailedToCreateDataDir)
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TableLayout {
    columns: HashMap<&'static str, ColumnOptions>,
}

impl TableLayout {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_columns(i: impl IntoIterator<Item = (&'static str, ColumnOptions)>) -> Self {
        Self {
            columns: HashMap::from_iter(i.into_iter()),
        }
    }

    pub fn column(&mut self, key: &'static str, opts: ColumnOptions) -> &mut Self {
        self.columns.insert(key, opts);

        self
    }

    pub fn columns(
        &mut self,
        i: impl IntoIterator<Item = (&'static str, ColumnOptions)>,
    ) -> &mut Self {
        self.columns.extend(i);

        self
    }

    pub fn column_names(&self) -> Vec<&'static str> {
        self.columns.keys().map(|k| *k).collect()
    }

    pub fn sql(&self) -> String {
        self.columns
            .iter()
            .map(|(col, opts)| opts.sql(col))
            .reduce(|acc, col| acc + ", " + &col)
            .unwrap_or_default()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ColumnOptions {
    unique: bool,
    nullable: bool,
    pk: bool,
    type_: Type,
}

impl Default for ColumnOptions {
    fn default() -> Self {
        Self {
            unique: true,
            nullable: false,
            pk: false,
            type_: Type::Integer,
        }
    }
}

impl core::str::FromStr for ColumnOptions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chunks = s.split('|');
        let Some(ty) = chunks.next() else {
            return Err(Error::InvalidConversionStr);
        };
        let type_ = sqlite_type_from_str(ty)?;
        let mut unique = false;
        let mut nullable = true;
        let mut pk = false;
        for chunk in chunks {
            update_column_option_from_str(chunk, &mut unique, &mut nullable, &mut pk)?
        }

        Ok(Self {
            type_,
            unique,
            nullable,
            pk,
        })
    }
}

fn update_column_option_from_str(
    s: &str,
    unique: &mut bool,
    nullable: &mut bool,
    pk: &mut bool,
) -> Result<(), Error> {
    match s {
        "u" => *unique = true,
        "nn" => *nullable = false,
        "pk" => *pk = true,
        _ => return Err(Error::InvalidConversionStr),
    }

    Ok(())
}

fn sqlite_type_from_str(s: &str) -> Result<Type, Error> {
    Ok(match s {
        "int" => Type::Integer,
        "null" => Type::Null,
        "real" => Type::Real,
        "text" => Type::Text,
        "blob" => Type::Blob,
        _ => return Err(Error::InvalidConversionStr),
    })
}

impl ColumnOptions {
    pub fn new(type_: Type) -> Self {
        Self {
            type_,
            ..Default::default()
        }
    }

    pub fn sql(&self, s: &str) -> String {
        let mut s = s.to_owned();
        s.push(' ');
        s.push_str(&self.type_.to_string());

        if self.pk {
            s.push_str(" primary key");
        }
        if !self.nullable {
            s.push_str(" not null");
        }
        if self.unique {
            s.push_str(" unique");
        }

        s
    }
}

// table either
// exists with the right columns -> do nothing
// doesnt exist -> make it
// exists with wrong columns -> remove it then make it anew | fix the columns
#[derive(Debug, Default, PartialEq, Eq, Clone, Hash)]
pub struct TableOptions {
    // make a new table using the layout iff it doesnt exist
    make: bool,
    // check if the table exists with the corrent layout
    // usually true, unless you know for a fact the table doesnt exist
    check: bool,
    // discard the existing table if any, and make a new one in case the check fails
    remake: bool,
}

impl TableOptions {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn make(&mut self, make: bool) -> &mut Self {
        self.make = make;
        self
    }

    pub fn check(&mut self, check: bool) -> &mut Self {
        self.check = check;
        self
    }

    pub fn remake(&mut self, remake: bool) -> &mut Self {
        self.remake = remake;
        self
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Table {
    name: &'static str,
    layout: TableLayout,
    options: TableOptions,
}

impl Table {
    pub fn new(name: &'static str, layout: TableLayout, options: TableOptions) -> Self {
        Self {
            name,
            layout,
            options,
        }
    }

    pub fn drop_from_db(&self, conn: &Connection) -> Result<(), Error> {
        conn.execute(&["drop table ", self.name].concat(), [])
            .map_err(|_| Error::FailedToDropTable)
            .map(|_| ())
    }

    pub fn check_columns(&self, conn: &Connection) -> Result<(), Error> {
        if !conn
            .prepare(&["select * from ", self.name, " limit 0"].concat())
            .map(|stt| stt.column_names() == self.layout.column_names().as_slice())
            .map_err(|_| Error::FailedToProcessQueryRow)?
        {
            return Err(Error::TableColumnsMismatch);
        }

        Ok(())
    }

    pub fn check(&self, tables: &[String]) -> Result<(), Error> {
        // let sql = [
        //     "select name from sqlite_master where type='table' and name='",
        //     self.name,
        //     "';",
        // ]
        // .concat();
        // println!(">>ct<< {}", sql);
        // let table_name: String = conn
        //     .query_row(&sql, [], |row| row.get(0))
        //     .map_err(|_| Error::FailedToProcessQueryRow)?;
        //
        // if table_name.as_str() != self.name {
        //     return Err(Error::TableNotFound);
        // }

        if !tables.contains(&self.name.to_owned()) {
            return Err(Error::TableNotFound);
        }

        Ok(())
    }

    pub fn sql(&self) -> String {
        [
            "create table ",
            self.name,
            " (",
            &self.layout.sql(),
            ") strict;",
        ]
        .concat()
    }

    pub fn make(&self, conn: &Connection) -> Result<String, Error> {
        conn.execute(&self.sql(), [])
            .map_err(|_| Error::TableCreateFailed)
            .map(|_| self.name.to_owned())
    }
}

#[derive(Debug)]
pub struct Database {
    conn: Connection,
    tables: Vec<Table>,
    state: Vec<String>,
}

fn get_db_tables(conn: &Connection) -> Result<Vec<String>, Error> {
    conn.prepare("select name from sqlite_master where type='table';")
        .map_err(|_| Error::FailedToProcessQueryRow)?
        .query([])
        .map_err(|_| Error::FailedToProcessQueryRow)?
        .mapped(|row| row.get::<usize, String>(0))
        .collect::<Result<Vec<String>, _>>()
        .map_err(|_| Error::FailedToProcessQueryRow)
}

impl Database {
    // NOTE `Connection::open` creates a new db if it doesnt exist
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let conn = Connection::open(path).map_err(|_| Error::FailedToOpenDB)?;
        let state: Vec<String> = get_db_tables(&conn)?;
        Ok(Self {
            conn,
            state,
            tables: Vec::new(),
        })
    }

    pub fn with_tables(
        path: impl AsRef<Path>,
        tables: impl IntoIterator<Item = Table>,
    ) -> Result<Self, Error> {
        let conn = Connection::open(path).map_err(|_| Error::FailedToOpenDB)?;
        let state = get_db_tables(&conn)?;

        Ok(Self {
            // NOTE `Connection::open` creates a new db if it doesnt exist
            tables: Vec::from_iter(tables.into_iter()),
            conn,
            state,
        })
    }

    pub fn push_state(&mut self, state: String) {
        self.state.push(state);
    }

    pub fn check(&mut self) -> Result<(), Error> {
        let mut state = core::mem::take(&mut self.state);

        let res = self
            .tables
            .iter()
            .map(|t| {
                if !t.options.check {
                    return Ok(());
                }
                // println!("checking table");

                match t.check(&state) {
                    ok @ Ok(_) => return ok,
                    e @ Err(Error::TableNotFound) => {
                        if t.options.make {
                            let name = t.make(&self.conn)?;
                            state.push(name);
                        } else {
                            return e;
                        }
                    }
                    _ => unreachable!("fn returns either ok or err:tablenotfound"),
                }
                // println!("checked table existence");

                match t.check_columns(&self.conn) {
                    Ok(()) => (),
                    e @ Err(Error::TableColumnsMismatch) => {
                        if t.options.remake {
                            t.drop_from_db(&self.conn)?;
                            t.make(&self.conn)?;
                        } else {
                            return e;
                        }
                    }
                    err => return err,
                }
                // println!("checked table columns");

                Ok(())
            })
            .collect();
        self.state = core::mem::take(&mut state);

        res
    }
}

#[derive(Debug)]
pub struct DBPipeline {
    dir: DataDir,
    databases: Vec<Database>,
}

impl DBPipeline {
    pub fn new(dir: DataDir) -> Self {
        Self {
            dir,
            databases: Vec::new(),
        }
    }

    pub fn with_dbs(dir: DataDir, dbs: impl IntoIterator<Item = Database>) -> Self {
        Self {
            dir,
            databases: Vec::from_iter(dbs.into_iter()),
        }
    }

    pub fn database(&mut self, db: Database) -> &mut Self {
        self.databases.push(db);

        self
    }

    pub fn check_dir(&self) -> Result<(), Error> {
        match self.dir.check() {
            e @ Err(Error::DataIsNotADir) => return e,
            Err(Error::DataDirNotFound) => self.dir.make(),
            ok @ Ok(()) => return ok,
            _ => unreachable!("function doesnt return this variant"),
        }
    }

    pub fn build(mut self) -> Result<(), Error> {
        self.check_dir()?;
        self.databases.iter_mut().map(|db| db.check()).collect()
    }
}
