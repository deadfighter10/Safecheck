pub const MARKUP_TYPES: &[&str] = &["html", "htm", "xhtml", "xht", "svg"];

pub const HIGH_RISK_EXTENSIONS: &[&str] = &[
    // Native executables / libraries
    "exe",
    "dll",
    "com",
    "scr",
    "cpl",
    "ocx",
    "sys",
    "drv",
    "app",

    // Installers / packages
    "msi",
    "msp",
    "mst",
    "cab",
    "pkg",
    "dmg",
    "iso",

    // Scripts / command files
    "bat",
    "cmd",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "sh",
    "bash",
    "zsh",
    "fish",
    "command",
    "pl",
    "py",
    "rb",

    // Shortcuts / link-like files
    "lnk",
    "url",
    "scf",
    "shb",
    "shs",

    // Java / .NET related executable content
    "jar",
    "class",

    // Macro-enabled Office documents
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppsm",
    "ppam",

    // Apple executable / bundle-related
    "dylib",
    "bundle",
    "framework",
];

pub const YARA_SCAN_EXTENSIONS: &[&str] = &[
    // Executables / native code
    "exe",
    "dll",
    "com",
    "scr",
    "cpl",
    "ocx",
    "sys",
    "drv",
    "dylib",
    "app",
    "bundle",
    "framework",
    "elf",
    "so",

    // Scripts / interpreted code
    "js",
    "jse",
    "mjs",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "sh",
    "bash",
    "zsh",
    "fish",
    "command",
    "py",
    "pl",
    "pm",
    "rb",
    "php",

    // Web / markup / active content
    "html",
    "htm",
    "xhtml",
    "xht",
    "xml",
    "svg",
    "hta",

    // Documents that can contain active content / macros
    "pdf",
    "rtf",
    "doc",
    "dot",
    "docm",
    "dotm",
    "xls",
    "xlt",
    "xlsm",
    "xltm",
    "xlam",
    "ppt",
    "pot",
    "pps",
    "pptm",
    "potm",
    "ppsm",
    "ppam",

    // Java / managed executable content
    "jar",
    "class",
    "war",
    "ear",

    // Installers / packages
    "msi",
    "msp",
    "pkg",
    "dmg",

    // Archives / containers
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "bz2",
    "xz",
    "iso",
];

pub const ACTIVE_CONTENT_MARKERS: &[&str] = &[
    "<script",
    "javascript:",
    "<iframe",
    "<object",
    "<embed",
    "http-equiv=\"refresh\"",
    // common event handlers
    "onload=", "onerror=", "onclick=", "onmouseover=", "onfocus=", "onanimationstart=",
];


pub const ENTROPY_EXECUTABLE_TYPES: &[&str] = &[
    "exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "com",
    "elf", "so", "mach", "dylib", "bundle",
    "class", "dex", "wasm", "obj",

    "sh", "bash", "zsh", "fish", "command",
    "ps1", "psm1", "bat", "cmd",
    "js", "jse", "mjs", "vbs", "vbe", "wsf", "wsh",
    "py", "pl", "pm", "rb", "php",

    "hta", "html", "htm", "xhtml", "xht", "svg",
];

pub const ENTROPY_DOCUMENT_TYPES: &[&str] = &[
    "doc", "dot", "xls", "xlt", "ppt", "pot", "pps",
    "rtf", "txt", "csv", "md", "json", "xml", "ps",
];

pub const ENTROPY_EXPECTED_HIGH: &[&str] = &[
    "zip", "gz", "bz2", "bz3", "xz", "7z", "rar", "zst", "lz", "lz4",
    "cab", "deb", "rpm", "dmg", "msi",
    "epub", "mobi", "jar", "war", "ear", "apk", "crx",
    "docx", "xlsx", "pptx", "odt", "ods", "odp",
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "ppam",
    "pdf",
    "jpg", "jpeg", "png", "gif", "webp", "heif", "avif", "jxl", "jp2",
    "mp3", "m4a", "aac", "ogg", "opus", "flac",
    "mp4", "m4v", "mkv", "webm", "mov", "avi", "wmv", "flv",
    "woff", "woff2", "swf",
];