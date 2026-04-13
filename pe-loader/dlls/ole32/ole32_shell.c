/*
 * ole32_shell.c - Previously contained shell function duplicates
 *
 * All shell functions (SHGetKnownFolderPath, SHGetFolderPathA/W,
 * SHGetSpecialFolderPathA, SHCreateDirectoryExA, SHFileOperationA,
 * SHGetFileInfoA, ShellExecuteA/W) have been removed.
 *
 * Their canonical home is shell32.dll (shell32_shell.c).
 * ole32 does not export shell functions on Windows.
 */
