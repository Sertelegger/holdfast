//! §3.6's capability matrix, as a **value** rather than a `#[cfg]`
//! branch.
//!
//! `#[cfg]` decides the **default**; the branch reads the value. That is
//! the whole reason this module exists: without it,
//! `not_supported_on_platform` (REQ-A-006, REQ-T-017) is a status
//! declared in the enum that no test on any machine CI runs on can
//! produce — and REQ-T-017's guard,
//! `every_declared_status_is_returned_by_a_real_response`, would have to
//! be weakened to let it ship. A `#[cfg(windows)] return …` inline in
//! the tool body buys the same behaviour and loses exactly that.

/// What this build of Holdfast can do on the platform it is running on.
///
/// `Clone` is not decoration: [`crate::mcp::HoldfastServer`] derives
/// `Clone` and holds one of these, so a non-`Clone` field would not
/// compile there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether a secret can be typed at an attached client and reach the
    /// child's PTY **without crossing the MCP wire** (§3.6, §9.5).
    ///
    /// `false` on Windows native, where §3.3/§3.6 leave stdio the only
    /// transport until 0.0.11 and sessions die with the shim: there is
    /// no daemon holding the session, so there is no out-of-band party
    /// to type into it.
    pub out_of_band_secret_input: bool,
}

// **Hand-written on purpose, and clippy is right only on one target.**
// `cfg!(unix)` folds to `false` on Windows, which is `bool::default()`, so
// `derivable_impls` fires there and nowhere else — the lint is reading a
// coincidence of this build rather than the shape of the type. Deriving
// would also make the answer depend on each field's `Default` instead of on
// the platform, so the next capability added would come out `false` on Unix
// too, silently. The `allow` is scoped to this impl rather than the module
// so it cannot cover a genuinely derivable one added later.
#[allow(clippy::derivable_impls)]
impl Default for Capabilities {
    fn default() -> Self {
        Self {
            out_of_band_secret_input: cfg!(unix),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `cfg!` is the *default*, and inverting it would disable the
    /// tool on every machine while passing every test that only drives
    /// the forced-`false` seam.
    #[test]
    fn the_default_capability_matches_the_platform() {
        let caps = Capabilities::default();
        #[cfg(unix)]
        assert!(
            caps.out_of_band_secret_input,
            "§3.6: out-of-band secret input is a Unix capability and this is a Unix build"
        );
        #[cfg(windows)]
        assert!(
            !caps.out_of_band_secret_input,
            "§3.6: Windows native has no daemon to type into"
        );
        // Neither arm compiles on a third platform, and a test that
        // asserts nothing at all is the failure this line prevents.
        #[cfg(not(any(unix, windows)))]
        compile_error!("§3.6's matrix covers Unix and Windows; add the arm before the platform");
        let _ = caps;
    }

    /// The seam itself: a forced value is what the branch reads, not the
    /// `cfg!`. Without this, `Capabilities` is a `#[cfg]` with extra
    /// steps.
    #[test]
    fn a_forced_capability_overrides_the_platform_default() {
        // Forced to the **opposite** of whatever this platform defaults
        // to, so the assertion is that the field is a value rather than
        // a `cfg!` — on either platform. Forcing a literal `false` would
        // prove nothing on Windows, where `false` is already the default.
        let default = Capabilities::default();
        let forced = Capabilities {
            out_of_band_secret_input: !default.out_of_band_secret_input,
        };
        assert_ne!(
            forced, default,
            "the capability is not readable as a value; the branch would be a `cfg!`"
        );
    }
}
