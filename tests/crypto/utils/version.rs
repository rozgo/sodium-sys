use regex::Regex;
use sodium_sys::crypto::utils::version;

#[test]
fn version() {
    let re = Regex::new(r"^\d{1}\.\d{1}\.\d{1}$").unwrap();
    assert!(re.is_match(version::version().unwrap()));
}

#[test]
fn library_version_major() {
    let re = Regex::new(r"^\d{1}$").unwrap();
    assert!(re.is_match(&version::library_version_major().to_string()[..]));
}

#[test]
fn library_version_minor() {
    let re = Regex::new(r"^\d{1}$").unwrap();
    assert!(re.is_match(&version::library_version_minor().to_string()[..]));
}
