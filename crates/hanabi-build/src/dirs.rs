use super::Error;
use std::env::{current_dir as cwd, set_current_dir as cd};
use std::path::{Path, PathBuf};

// #[derive(Debug, Clone)]
// pub enum Error {
//     CwdCallFailed,
//     CdCallFailed,
//     DirNotFound,
//     DirIsNoDir,
//     MkdirCallFailed,
// }

#[derive(Debug, Clone)]
pub struct Dir(PathBuf);

impl Dir {
    pub fn new() -> Result<Self, Error> {
        cwd()
            .map(|pb| Self(pb))
            .map_err(|_| Error::DirsCwdCallFailed)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Self {
        Self(PathBuf::from(path.as_ref()))
    }

    pub fn push(&mut self, path: impl AsRef<Path>) {
        self.0.push(path);
    }

    pub fn as_str(&self) -> Option<&str> {
        self.0.as_os_str().to_str()
    }

    pub fn goto(&self) -> Result<(), Error> {
        cd(&self.0).map_err(|_| Error::DirsCdCallFailed)
    }

    pub fn is_dir(&self) -> Result<(), Error> {
        if !self.0.exists() {
            return Err(Error::DirsDirNotFound);
        } else if !self.0.is_dir() {
            return Err(Error::DirsDirIsNoDir);
        }

        Ok(())
    }

    pub fn make(&self) -> Result<(), Error> {
        std::fs::create_dir(&self.0).map_err(|_| Error::DirsMkdirCallFailed)
    }
}
