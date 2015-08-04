use regex::Regex;
use sodium_sys::version;

#[test]
fn version() {
    let re = Regex::new(r"^\d{1}\.\d{1}\.\d{1}$").unwrap();
    assert!(re.is_match(ss_version_string().unwrap()));
}

#[test]
fn library_version_major() {
    let re = Regex::new(r"^\d{1}$").unwrap();
    assert!(re.is_match(&ss_library_version_major().to_string()[..]));
}

#[test]
fn library_version_minor() {
    let re = Regex::new(r"^\d{1}$").unwrap();
    assert!(re.is_match(&ss_library_version_minor().to_string()[..]));
}
