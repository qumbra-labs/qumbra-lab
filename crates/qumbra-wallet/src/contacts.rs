//! `contacts.v1` — local names for full receive addresses.
//!
//! ```text
//!   <wallet dir>/contacts.v1   0600, versioned, reject-unknown
//! ```
//!
//! This is convenience, not verification. The full `qaddr1…` remains the
//! authority and every display path keeps its `qs1…` fingerprint visible.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use qlab_wallet::address::Address;

pub const CONTACTS_FILE: &str = "contacts.v1";
pub const CONTACTS_HEADER: &str = "qumbra-wallet contacts v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub name: String,
    /// The canonical full `qaddr1…` encoding, never the short fingerprint.
    pub address: String,
}

impl Contact {
    pub fn decoded(&self) -> Address {
        // Every construction and load path validates through Address::decode.
        // Keeping the invariant private makes this infallible to callers.
        Address::decode(&self.address).expect("validated contact address")
    }

    pub fn short(&self) -> String {
        self.decoded().short().encode()
    }
}

#[derive(Debug)]
pub enum ContactError {
    Io(io::Error),
    BadHeader {
        path: PathBuf,
        got: String,
    },
    BadRecord {
        path: PathBuf,
        line: usize,
        why: String,
    },
    InvalidName {
        name: String,
        why: &'static str,
    },
    InvalidAddress,
    DuplicateName(String),
    UnknownName(String),
}

impl std::fmt::Display for ContactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContactError::Io(e) => write!(f, "contact book I/O: {e}"),
            ContactError::BadHeader { path, got } => write!(
                f,
                "unreadable contact book {}: header {got:?}; this binary knows \
                 `{CONTACTS_HEADER}` only",
                path.display()
            ),
            ContactError::BadRecord { path, line, why } => write!(
                f,
                "unreadable contact book {} at line {line}: {why}. Refusing to read a file this \
                 binary only partly understands",
                path.display()
            ),
            ContactError::InvalidName { name, why } => {
                write!(f, "invalid contact name `{name}`: {why}")
            }
            ContactError::InvalidAddress => write!(
                f,
                "contact address is not a valid full qaddr1… address \
                 (wrong HRP, checksum, version, or length refused)"
            ),
            ContactError::DuplicateName(name) => {
                write!(f, "contact name `{name}` already exists")
            }
            ContactError::UnknownName(name) => write!(f, "unknown contact `{name}`"),
        }
    }
}

impl std::error::Error for ContactError {}

impl From<io::Error> for ContactError {
    fn from(value: io::Error) -> Self {
        ContactError::Io(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContactBook {
    contacts: Vec<Contact>,
}

impl ContactBook {
    /// An absent book is an empty book. Every present byte is parsed under the
    /// exact v1 schema before any contact is returned.
    pub fn load(dir: &Path) -> Result<ContactBook, ContactError> {
        let path = dir.join(CONTACTS_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ContactBook::default()),
            Err(e) => return Err(e.into()),
        };
        parse(&path, &text)
    }

    pub fn entries(&self) -> &[Contact] {
        &self.contacts
    }

    pub fn resolve(&self, name: &str) -> Result<Address, ContactError> {
        self.contacts
            .iter()
            .find(|contact| contact.name == name)
            .map(Contact::decoded)
            .ok_or_else(|| ContactError::UnknownName(name.to_string()))
    }

    pub fn add(dir: &Path, name: &str, address: &str) -> Result<Contact, ContactError> {
        validate_name(name)?;
        let decoded = Address::decode(address).ok_or(ContactError::InvalidAddress)?;
        let mut book = Self::load(dir)?;
        if book.contacts.iter().any(|contact| contact.name == name) {
            return Err(ContactError::DuplicateName(name.to_string()));
        }
        let contact = Contact {
            name: name.to_string(),
            address: decoded.encode(),
        };
        book.contacts.push(contact.clone());
        book.save(dir)?;
        Ok(contact)
    }

    pub fn remove(dir: &Path, name: &str) -> Result<Contact, ContactError> {
        validate_name(name)?;
        let mut book = Self::load(dir)?;
        let position = book
            .contacts
            .iter()
            .position(|contact| contact.name == name)
            .ok_or_else(|| ContactError::UnknownName(name.to_string()))?;
        let removed = book.contacts.remove(position);
        book.save(dir)?;
        Ok(removed)
    }

    fn save(&self, dir: &Path) -> Result<(), ContactError> {
        let path = dir.join(CONTACTS_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // OpenOptionsExt controls newly-created files; this also repairs a
            // pre-existing file whose mode was widened out of band.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        writeln!(file, "{CONTACTS_HEADER}")?;
        for contact in &self.contacts {
            writeln!(
                file,
                "contact\tname_hex={}\taddress={}",
                encode_hex(contact.name.as_bytes()),
                contact.address
            )?;
        }
        file.sync_all()?;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), ContactError> {
    if name.is_empty() {
        return Err(ContactError::InvalidName {
            name: name.to_string(),
            why: "it is empty",
        });
    }
    if name.chars().any(char::is_control) {
        return Err(ContactError::InvalidName {
            name: name.to_string(),
            why: "control characters are not allowed",
        });
    }
    Ok(())
}

fn parse(path: &Path, text: &str) -> Result<ContactBook, ContactError> {
    let mut lines = text.lines().enumerate();
    match lines.next() {
        Some((_, header)) if header == CONTACTS_HEADER => {}
        other => {
            return Err(ContactError::BadHeader {
                path: path.to_path_buf(),
                got: other
                    .map(|(_, header)| header.to_string())
                    .unwrap_or_default(),
            })
        }
    }

    let mut contacts: Vec<Contact> = Vec::new();
    for (index, line) in lines {
        let line_number = index + 1;
        if line.is_empty() {
            continue;
        }
        let bad = |why: String| ContactError::BadRecord {
            path: path.to_path_buf(),
            line: line_number,
            why,
        };
        let mut fields = line.split('\t');
        if fields.next() != Some("contact") {
            return Err(bad("record kind is not `contact`".into()));
        }
        let (mut name, mut address) = (None, None);
        for field in fields {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| bad(format!("field {field:?} is not key=value")))?;
            match key {
                "name_hex" if name.is_none() => {
                    let bytes = decode_hex(value)
                        .ok_or_else(|| bad("name_hex is not even-length hexadecimal".into()))?;
                    let decoded = String::from_utf8(bytes)
                        .map_err(|_| bad("name_hex is not UTF-8".into()))?;
                    validate_name(&decoded).map_err(|e| bad(e.to_string()))?;
                    name = Some(decoded);
                }
                "address" if address.is_none() => {
                    let decoded = Address::decode(value)
                        .ok_or_else(|| bad("address is not a valid full qaddr1… address".into()))?;
                    address = Some(decoded.encode());
                }
                "name_hex" | "address" => return Err(bad(format!("duplicate field `{key}`"))),
                other => return Err(bad(format!("unknown field `{other}`"))),
            }
        }
        let contact = Contact {
            name: name.ok_or_else(|| bad("missing name_hex".into()))?,
            address: address.ok_or_else(|| bad("missing address".into()))?,
        };
        if contacts
            .iter()
            .any(|existing| existing.name == contact.name)
        {
            return Err(bad(format!("duplicate contact name `{}`", contact.name)));
        }
        contacts.push(contact);
    }
    Ok(ContactBook { contacts })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::MasterSeed;
    use qlab_wallet::Wallet;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qmb_wallet_contacts_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn address(index: u64) -> Address {
        Wallet::from_master_seed(&MasterSeed::from_entropy([9; 32]), 0).address_at_index(index)
    }

    #[test]
    fn contacts_v1_round_trips_full_addresses_and_is_owner_only() {
        let dir = tmp("roundtrip");
        let full = address(0).encode();
        let added = ContactBook::add(&dir, "Alice Smith", &full).unwrap();
        assert_eq!(
            added.address, full,
            "the full receiving address is retained"
        );

        let loaded = ContactBook::load(&dir).unwrap();
        assert_eq!(loaded.entries(), &[added]);
        assert_eq!(loaded.resolve("Alice Smith").unwrap().encode(), full);
        assert!(std::fs::read_to_string(dir.join(CONTACTS_FILE))
            .unwrap()
            .starts_with(&format!("{CONTACTS_HEADER}\n")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CONTACTS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "contact names and addresses are owner-only"
            );
        }
    }

    #[test]
    fn contacts_v1_rejects_unknown_schema_and_invalid_addresses() {
        let dir = tmp("reject");
        let path = dir.join(CONTACTS_FILE);
        std::fs::write(&path, "qumbra-wallet contacts v9\n").unwrap();
        assert!(matches!(
            ContactBook::load(&dir),
            Err(ContactError::BadHeader { .. })
        ));

        let full = address(1);
        std::fs::write(
            &path,
            format!(
                "{CONTACTS_HEADER}\ncontact\tname_hex=616c696365\taddress={}\tverified=true\n",
                full.encode()
            ),
        )
        .unwrap();
        let error = ContactBook::load(&dir).unwrap_err().to_string();
        assert!(error.contains("unknown field `verified`"), "{error}");

        std::fs::remove_file(&path).unwrap();
        let error = ContactBook::add(&dir, "alice", &full.short().encode())
            .unwrap_err()
            .to_string();
        assert!(error.contains("wrong HRP"), "{error}");
        assert!(!path.exists(), "a refused address writes no contact book");
    }

    #[test]
    fn duplicate_and_unknown_names_are_refused_by_name_and_remove_persists() {
        let dir = tmp("names");
        ContactBook::add(&dir, "alice", &address(0).encode()).unwrap();
        let duplicate = ContactBook::add(&dir, "alice", &address(1).encode())
            .unwrap_err()
            .to_string();
        assert!(duplicate.contains("`alice` already exists"), "{duplicate}");

        let unknown = match ContactBook::load(&dir).unwrap().resolve("mallory") {
            Ok(_) => panic!("an unknown name must not resolve"),
            Err(error) => error.to_string(),
        };
        assert_eq!(unknown, "unknown contact `mallory`");
        let removed = ContactBook::remove(&dir, "alice").unwrap();
        assert_eq!(removed.name, "alice");
        assert!(ContactBook::load(&dir).unwrap().entries().is_empty());
        assert_eq!(
            ContactBook::remove(&dir, "alice").unwrap_err().to_string(),
            "unknown contact `alice`"
        );
    }
}
