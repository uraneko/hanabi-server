use super::Error;
use std::process::{Command as Cmd, ExitStatus};

// #[derive(Debug, Clone)]
// pub enum Error {
//     InvalidDirsInstance,
//     FailedToBuildJsPackage,
//     FailedToCopyPackageFiles,
// }

#[derive(Debug)]
pub struct UiPipeline<'a> {
    copy: Option<[&'a str; 2]>,
    build: Option<&'a [&'a str]>,
}

impl<'a> UiPipeline<'a> {
    pub fn new() -> Self {
        Self {
            copy: None,
            build: None,
        }
    }

    pub fn build(mut self, build: &'a [&'a str]) -> Self {
        self.build = Some(build);

        self
    }

    pub fn copy(mut self, copy: [&'a str; 2]) -> Self {
        self.copy = Some(copy);

        self
    }

    pub fn update(self) -> Result<(), Error> {
        if let Some(cmd) = self.build {
            build_ui(cmd)?;
        }

        if let Some([from, to]) = self.copy {
            _ = copy_ui(from, to)?;
        }

        Ok(())
    }
}

fn build_ui(cmd: &[&str]) -> Result<ExitStatus, Error> {
    Cmd::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .map_err(|_| Error::UiFailedToBuildJsPackage)
}

fn copy_ui(from: &str, to: &str) -> Result<ExitStatus, Error> {
    Cmd::new("cp")
        // .args(&["build", "-r", "../../../rust/hanabi"])
        .args(&[from, "-r", to])
        .status()
        .map_err(|_| Error::UiFailedToCopyPackageFiles)
}
