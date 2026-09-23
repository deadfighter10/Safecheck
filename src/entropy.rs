use anyhow::Result;
use derive_more::Display;
use crate::report::{Finding, Issue, Report, Severity, SubSystem};

#[derive(PartialEq, Debug, Clone, Copy, Display)]
pub(crate) enum WindowKind {
    Normal,
    Compressed,
    TooUniform,
    RandomLooking
}

#[derive(PartialEq, Debug, Clone, Copy)]
struct Region {
    start: usize,
    end: usize,
    max_entropy: f64,
    max_chi2: f64,
    kind: WindowKind
}


const WINDOW: usize = 4096;
const STRIDE: usize = WINDOW/2;
const MIN_REGION_BYTES: usize = 10 * 1024;

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

pub fn get_entropy(bytes: &[u8], report: &mut Report) -> Result<()> {
    let Some(type_severity) = entropy_severity(report.reported_filetype.as_str(), report.real_filetype.extension()) else {
        return Ok(());
    };


    if bytes.len() < WINDOW {
        return Ok(());
    }

    let mut counts = [0u32; 256];
    for &b in &bytes[0..WINDOW] {
        counts[b as usize] += 1;
    }

    let mut start = 0;
    let mut regions = Vec::new();

    while start + WINDOW <= bytes.len() {
        let (entropy, chi2) = window_stat(&counts, WINDOW);

        regions.push(Region::new(
            start,
            start + WINDOW,
            entropy,
            chi2
        ));

        let next = start + STRIDE;
        if next + WINDOW > bytes.len() { break; }

        for &b in &bytes[start..next] { counts[b as usize] -= 1; }
        for &b in &bytes[start + WINDOW..next + WINDOW] { counts[b as usize] += 1; }
        start = next;
    }

    collapse_regions(&mut regions);

    for region in regions {
        if region.end - region.start < MIN_REGION_BYTES {
            continue;
        }

        let severity = match region.kind {
            WindowKind::Normal => continue,
            WindowKind::TooUniform => Severity::Low,
            WindowKind::Compressed | WindowKind::RandomLooking => type_severity,
        };

        report.add_finding(Finding::new(
            report.filepath.clone(),
            Issue::HighEntropy {
                kind: region.kind,
                start: region.start,
                end: region.end,
                entropy: region.max_entropy,
                chi2: region.max_chi2,
            },
            severity,
            SubSystem::Entropy,
        ));
    }

    Ok(())
}

fn entropy_severity(reported_ext: &str, detected_ext: &str) -> Option<Severity> {
    let reported = reported_ext.to_lowercase();
    let ext = if detected_ext.is_empty() { reported.as_str() } else { detected_ext };

    if ENTROPY_EXPECTED_HIGH.contains(&ext) {
        if detected_ext.is_empty() {
            // Named like a compressed format, but the magic bytes don't confirm it
            return Some(Severity::Medium);
        }
        return None;
    }
    if ENTROPY_EXECUTABLE_TYPES.contains(&ext) {
        return Some(Severity::High);
    }
    if ENTROPY_DOCUMENT_TYPES.contains(&ext) {
        return Some(Severity::Medium);
    }
    Some(Severity::Low)
}

fn window_stat(counts: &[u32; 256], n: usize) -> (f64, f64) {
    let n = n as f64;
    let randomness = n / 256.0;
    let mut entropy = 0.0;
    let mut chi2 = 0.0;

    for &c in counts {
        let c = c as f64;
        if c > 0.0 {
            let p = c / n;
            entropy -= p * p.log2();
        }
        let diff = c - randomness;
        chi2 += diff * diff / randomness;
    }

    (entropy, chi2)
}

impl Region {
    pub fn new(start: usize, end: usize, entropy: f64, chi2: f64) -> Region {
        Region {
            start,
            end,
            max_entropy: entropy,
            max_chi2: chi2,
            kind: classify(entropy, chi2),
        }
    }
}

fn classify(entropy: f64, chi2: f64) -> WindowKind {
    if entropy < 7.2 {
        WindowKind::Normal
    } else if chi2 > 330.0 {
        WindowKind::Compressed
    } else if chi2 < 190.0 {
        WindowKind::TooUniform
    } else {
        WindowKind::RandomLooking
    }
}

fn collapse_regions(regions: &mut Vec<Region>) {
    if regions.is_empty() {return;}
    let mut new_regions = Vec::new();
    let mut i = 0usize;
    let mut f = 1usize;
    let mut max_entropy:f64 = regions[0].max_entropy;
    let mut max_chi2:f64 = regions[0].max_chi2;
    while i < regions.len()-1 {
        while f < regions.len() {
            if regions[i].kind != regions[f].kind {
                new_regions.push(Region::new(
                    regions[i].start,
                    regions[f-1].end,
                    max_entropy,
                    max_chi2,
                ));
                i=f;
                max_entropy = regions[f].max_entropy;
                max_chi2 = regions[f].max_chi2;
            } else {
                max_entropy = max_entropy.max(regions[f].max_entropy);
                max_chi2 = max_chi2.max(regions[f].max_chi2);
            }
            f+=1;
        }

        break
    }
    new_regions.push(Region::new(
        regions[i].start,
        regions[f-1].end,
        max_entropy,
        max_chi2,
    ));

    *regions = new_regions;
}
