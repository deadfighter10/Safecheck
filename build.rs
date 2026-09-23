use std::env;
use std::fs;
use std::path::Path;


fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = Path::new(&manifest_dir).join("src");
    let index_path = src_dir.join("rules").join("malware_index.yar");

    println!("cargo:rerun-if-changed={}", index_path.display());
    println!("cargo:rerun-if-changed={}", src_dir.join("rules").join("malware").display());

    let index = fs::read_to_string(&index_path).expect("cannot read malware_index.yar");

    let mut generated = String::from("pub const RULE_FILES: &[(&str, &str)] = &[\n");

    for line in index.lines() {
        let Some(rest) = line.trim().strip_prefix("include \"") else { continue };
        let Some(relative) = rest.strip_suffix('"') else { continue };

        let full_path = src_dir.join(relative);
        if !full_path.exists() {
            println!("cargo:warning=rule file listed in index but missing: {relative}");
            continue;
        }

        let name = Path::new(relative).file_name().unwrap().to_string_lossy();
        generated.push_str(&format!(
            "    ({:?}, include_str!({:?})),\n",
            name,
            full_path.to_string_lossy()
        ));
    }

    generated.push_str("];\n");

    let out_path = Path::new(&env::var("OUT_DIR").unwrap()).join("yara_rules.rs");
    fs::write(out_path, generated).expect("cannot write generated rule list");
}