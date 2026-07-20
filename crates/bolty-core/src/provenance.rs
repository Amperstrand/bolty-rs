/// Provenance of a key, tracking where it originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProvenance {
    FactoryDefault,
    DerivedIssuer { version: u8 },
    StaticTestKey,
    UnknownExternal,
}

impl KeyProvenance {
    /// Returns the bracket-tag form used in audit log lines.
    pub fn to_audit_tag(&self) -> String {
        match self {
            KeyProvenance::FactoryDefault => "FactoryDefault".to_string(),
            KeyProvenance::DerivedIssuer { version } => format!("DerivedIssuer({version})"),
            KeyProvenance::StaticTestKey => "StaticTestKey".to_string(),
            KeyProvenance::UnknownExternal => "UnknownExternal".to_string(),
        }
    }

    /// Returns the flat JSON name (no version).
    pub fn as_json_name(&self) -> &'static str {
        match self {
            KeyProvenance::FactoryDefault => "FactoryDefault",
            KeyProvenance::DerivedIssuer { .. } => "DerivedIssuer",
            KeyProvenance::StaticTestKey => "StaticTestKey",
            KeyProvenance::UnknownExternal => "UnknownExternal",
        }
    }

    /// Returns the version for DerivedIssuer, None otherwise.
    pub fn json_version(&self) -> Option<u8> {
        match self {
            KeyProvenance::DerivedIssuer { version } => Some(*version),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_formats() {
        assert_eq!(
            KeyProvenance::FactoryDefault.to_audit_tag(),
            "FactoryDefault"
        );
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 1 }.to_audit_tag(),
            "DerivedIssuer(1)"
        );
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 200 }.to_audit_tag(),
            "DerivedIssuer(200)"
        );
        assert_eq!(KeyProvenance::StaticTestKey.to_audit_tag(), "StaticTestKey");
        assert_eq!(
            KeyProvenance::UnknownExternal.to_audit_tag(),
            "UnknownExternal"
        );
    }

    #[test]
    fn json_names() {
        assert_eq!(
            KeyProvenance::FactoryDefault.as_json_name(),
            "FactoryDefault"
        );
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 1 }.as_json_name(),
            "DerivedIssuer"
        );
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 200 }.as_json_name(),
            "DerivedIssuer"
        );
        assert_eq!(KeyProvenance::StaticTestKey.as_json_name(), "StaticTestKey");
        assert_eq!(
            KeyProvenance::UnknownExternal.as_json_name(),
            "UnknownExternal"
        );
    }

    #[test]
    fn json_version_for_each_variant() {
        assert_eq!(KeyProvenance::FactoryDefault.json_version(), None);
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 1 }.json_version(),
            Some(1)
        );
        assert_eq!(
            KeyProvenance::DerivedIssuer { version: 200 }.json_version(),
            Some(200)
        );
        assert_eq!(KeyProvenance::StaticTestKey.json_version(), None);
        assert_eq!(KeyProvenance::UnknownExternal.json_version(), None);
    }
}
