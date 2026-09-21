# Safecheck
## Description
This project is a simple security tool to check suspicious files statically to see if they are likely or not to contain 
any malicious code. The whole project was written in rust, and is cross-platform.

## Examples
```bash
safecheck test_infected.epub

=====================
THREAT ANALYSIS
=====================
CRITICAL THREATS: 0
HIGH THREATS: 3
MEDIUM THREATS: 0
LOW THREATS: 1


BASE DATA
Checksum: 40db930f650f9ea0e7d3f61d965ec169c3c70bd92990426c2b69d6d1d432f22c
Length of file: 1539
Is file: true
Is folder: false
Reported extension epub
Real extension: epub
MIME type: application/epub+zip

YARA SUBSYSTEM
No Yara errors found.

ARCHIVE SUBSYSTEM
Path: OEBPS/empty.dat | Issue: Size | Severity: Low
Path: OEBPS/cover.exe | Issue: HighRiskFileType | Problem: reported: exe | detected: unknown | Severity: High
Path: OEBPS/notes.js | Issue: HighRiskFileType | Problem: reported: js | detected: unknown | Severity: High
Path: OEBPS/chapter1.xhtml | Issue: HighRiskFileType | Problem: reported: xhtml | detected: html | Severity: High
```

## Install
Installation is fairly easy with git and rust:
```
git clone https://github.com/deadfighter10/Safecheck.git
cd Safecheck

cargo install --path .
```

If you don't have rust, this website helps the installation with rustup:  
https://rust-lang.org/tools/install/

## Contribute
If you want to contribute, you can clone the project with:
```
git clone https://github.com/deadfighter10/Safecheck.git
cd Safecheck

cargo build
```
The test_infected.epub only contains harmless signals, it isn't a real infected file.

Feel free to contribute anything, but master is protected, and you need to create a new branch,
work on that and then create a PR to contribute. 

The project is distributed under the GNU GPLv3.