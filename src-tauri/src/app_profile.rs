//! Persistent security state follows the identifier compiled into the app and its helper.
pub(crate) struct Profile {
    suffix: String,
}
impl Profile {
    pub(crate) fn new(identifier: &str) -> Self {
        // Hex keeps distinct identifiers separate on case-insensitive filesystems and registries.
        let suffix = if identifier == "app.frameleaf.desktop" {
            String::new()
        } else {
            format!(
                "-{}",
                identifier
                    .bytes()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
        };
        Self { suffix }
    }
    pub(crate) fn service(&self) -> String {
        format!("app.frameleaf.desktop{}", self.suffix)
    }
    #[cfg(any(unix, test))]
    pub(crate) fn security_directory(&self) -> String {
        format!(".frameleaf-desktop-security{}", self.suffix)
    }
    #[cfg(any(windows, test))]
    pub(crate) fn mutex_name(&self, sid: &str) -> String {
        format!("Global\\FrameleafRuntimeEpochsV1{}-{sid}\0", self.suffix)
    }
    #[cfg(any(windows, test))]
    pub(crate) fn registry_key(&self) -> String {
        format!("Software\\Frameleaf\\DesktopSecurity{}\0", self.suffix)
    }
}
#[cfg(test)]
mod tests {
    use super::Profile;
    #[test]
    fn production_keeps_all_existing_security_locations() {
        let profile = Profile::new("app.frameleaf.desktop");
        assert_eq!(profile.service(), "app.frameleaf.desktop");
        assert_eq!(profile.security_directory(), ".frameleaf-desktop-security");
        assert_eq!(
            profile.mutex_name("S-1-5-21"),
            "Global\\FrameleafRuntimeEpochsV1-S-1-5-21\0"
        );
        assert_eq!(
            profile.registry_key(),
            "Software\\Frameleaf\\DesktopSecurity\0"
        );
    }
    #[test]
    fn separate_app_identifiers_never_share_credentials_or_identity_locations() {
        let production = Profile::new("app.frameleaf.desktop");
        let development = Profile::new("app.frameleaf.desktop.development");
        let qualification = Profile::new("app.frameleaf.desktop.Development");
        for profile in [&development, &qualification] {
            assert_ne!(profile.service(), production.service());
            assert_ne!(
                profile.security_directory(),
                production.security_directory()
            );
            assert_ne!(
                profile.mutex_name("S-1-5-21"),
                production.mutex_name("S-1-5-21")
            );
            assert_ne!(profile.registry_key(), production.registry_key());
        }
        assert_ne!(
            development.service().to_ascii_lowercase(),
            qualification.service().to_ascii_lowercase()
        );
        assert_ne!(
            development.security_directory().to_ascii_lowercase(),
            qualification.security_directory().to_ascii_lowercase()
        );
        assert_ne!(
            development.mutex_name("S-1-5-21").to_ascii_lowercase(),
            qualification.mutex_name("S-1-5-21").to_ascii_lowercase()
        );
        assert_ne!(
            development.registry_key().to_ascii_lowercase(),
            qualification.registry_key().to_ascii_lowercase()
        );
    }
}
