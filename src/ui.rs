use std::env::{current_dir as cwd, set_current_dir as cd};
use std::path::{Path, PathBuf};
use std::process::{Command as Cmd, ExitStatus};

#[derive(Debug, Clone)]
pub enum Error {
    FailedToInitWorkDir,
    FailedToChangeDir,
    FailedToBuildPnpmPackage,
    FailedToCopyFiles,
}

#[derive(Clone)]
pub struct WorkDir(PathBuf);

impl WorkDir {
    pub fn new() -> Result<Self, Error> {
        cwd()
            .map(|pb| Self(pb))
            .map_err(|_| Error::FailedToInitWorkDir)
    }

    pub fn dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.0 = PathBuf::from(dir.as_ref());

        self
    }

    pub fn dir_ref(&self) -> &str {
        self.0.as_os_str().to_str().unwrap_or("")
    }

    pub fn travel(&self) -> Result<(), Error> {
        cd(&self.0).map_err(|_| Error::FailedToChangeDir)?;

        Ok(())
    }
}

pub struct UIPipeline {
    copy: bool,
    build: bool,
}

impl UIPipeline {
    pub fn new() -> Self {
        Self {
            copy: true,
            build: true,
        }
    }

    pub fn build(mut self, build: bool) -> Self {
        self.build = build;

        self
    }

    pub fn copy(mut self, copy: bool) -> Self {
        self.copy = copy;

        self
    }

    pub fn update(self, build_path: impl AsRef<Path>, copy_path: &str) -> Result<(), Error> {
        let cargo_dir = WorkDir::new()?;
        let pnpm_dir = cargo_dir.clone().dir(build_path);
        pnpm_dir.travel()?;

        if self.build {
            build_ui()?;
        }

        if self.copy {
            copy_ui(copy_path).map(|_| ())?
        }
        cargo_dir.travel()?;

        Ok(())
    }
}

fn build_ui() -> Result<ExitStatus, Error> {
    Cmd::new("pnpm")
        .arg("build")
        .status()
        .map_err(|_| Error::FailedToBuildPnpmPackage)
}

fn copy_ui(path: &str) -> Result<ExitStatus, Error> {
    Cmd::new("cp")
        // .args(&["build", "-r", "../../../rust/hanabi"])
        .args(&["build", "-r", path])
        .status()
        .map_err(|_| Error::FailedToCopyFiles)
}
