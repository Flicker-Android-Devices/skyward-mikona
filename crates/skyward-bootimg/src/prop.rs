//! Recovery `prop.default` filtering and patching helpers shared between
//! offline packing (`skyward-pack`) and on-device persistence (`skyward-install`).

/// What a recovery image says about the build it is: the version and patch
/// levels of its own ramdisk's system and vendor partition, which are older
/// than those installed beside it whenever the phone has taken an update.
const BUILD_VERSION: [&str; 3] = ["ro.build.version.release", "ro.build.version.security_patch", "ro.vendor.build.security_patch"];

const RECOVERY_PROPS: [&str; 4] = ["ro.secure", "ro.adb.secure", "ro.debuggable", "ro.ota.allow_downgrade"];

const RECOVERY_OVERRIDES: &[u8] = b"ro.secure=0\nro.adb.secure=0\nro.debuggable=1\nro.ota.allow_downgrade=true\n";

/// A property file without the lines that set any of `names`.
pub fn without(props: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(props.len());
    for line in props.split_inclusive(|b| *b == b'\n') {
        let key = line.split(|b| *b == b'=').next().unwrap_or_default();
        if !names.iter().any(|n| n.as_bytes() == key) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Strip stale build/patch levels and idempotently ensure Skyward's recovery
/// properties (`ro.secure=0`, `ro.adb.secure=0`, `ro.debuggable=1`,
/// `ro.ota.allow_downgrade=true`).
pub fn patch_default(props: &[u8]) -> Vec<u8> {
    let mut strip = Vec::with_capacity(BUILD_VERSION.len() + RECOVERY_PROPS.len());
    strip.extend_from_slice(&BUILD_VERSION);
    strip.extend_from_slice(&RECOVERY_PROPS);
    let mut out = without(props, &strip);
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(RECOVERY_OVERRIDES);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_that_set_a_name_are_the_only_ones_left_out() {
        let props = b"ro.build.id=TQ\nro.build.version.release=13\nro.build.version.release_or_codename=13\nro.product.name=ishtar\n\
ro.vendor.build.security_patch=2026-10-01\nro.vendor.build.security_patch_level=1\n";
        let out = without(props, &BUILD_VERSION);
        let text = String::from_utf8(out).expect("property files are text");
        assert!(!text.contains("ro.build.version.release=13"));
        assert!(!text.contains("ro.vendor.build.security_patch=2026-10-01"));
        assert!(text.contains("ro.build.version.release_or_codename=13"));
        assert!(text.contains("ro.vendor.build.security_patch_level=1"));
        assert!(text.contains("ro.build.id=TQ") && text.contains("ro.product.name=ishtar"));
    }

    #[test]
    fn a_file_without_a_last_newline_keeps_its_last_line() {
        let out = without(b"a=1\nro.build.version.release=13", &BUILD_VERSION);
        assert_eq!(out, b"a=1\n");
        let kept = without(b"a=1\nb=2", &BUILD_VERSION);
        assert_eq!(kept, b"a=1\nb=2");
    }

    #[test]
    fn patch_default_is_idempotent_and_adds_recovery_props() {
        let first = patch_default(b"ro.product.name=thyme\nro.build.version.release=13\nro.adb.secure=1\n");
        let first_text = String::from_utf8(first.clone()).unwrap();
        assert!(!first_text.contains("ro.build.version.release="));
        assert!(!first_text.contains("ro.adb.secure=1"));
        assert!(first_text.contains("ro.product.name=thyme"));
        assert!(first_text.contains("ro.adb.secure=0"));
        assert!(first_text.contains("ro.ota.allow_downgrade=true"));
        assert_eq!(patch_default(&first), first);
    }
}
