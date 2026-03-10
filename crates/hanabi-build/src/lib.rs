pub mod db;
pub mod dirs;
pub mod ui;

#[derive(Debug, Clone)]
pub enum Error {
    DbFailedToOpenDB,
    DbFailedToProcessQueryRow,
    DbTableNotFound,
    DbFailedToDropTable,
    DbTableCreateFailed,
    DbTableColumnsMismatch,
    DbInvalidConversionStr,
    UiInvalidDirsInstance,
    UiFailedToBuildJsPackage,
    UiFailedToCopyPackageFiles,
    DirsCwdCallFailed,
    DirsCdCallFailed,
    DirsDirNotFound,
    DirsDirIsNoDir,
    DirsMkdirCallFailed,
}
