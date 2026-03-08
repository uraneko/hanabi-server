pub mod db;
pub mod ui;

#[derive(Debug, Clone)]
pub enum Error {
    DB(db::Error),
    UI(ui::Error),
}

impl From<db::Error> for Error {
    fn from(err: db::Error) -> Self {
        Self::DB(err)
    }
}

impl From<ui::Error> for Error {
    fn from(err: ui::Error) -> Self {
        Self::UI(err)
    }
}
