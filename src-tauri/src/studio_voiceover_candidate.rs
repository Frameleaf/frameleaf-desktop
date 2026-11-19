//! Optional, qualification-only Studio voice-over files inside the verified host payload.
use crate::native_runtime::Artifact;
use std::collections::BTreeMap;

const ROOT: &str = "studio/kokoro/";
const REQUIRED_FILES: &[&str] = &[
    "app/scripts/frameleaf-studio-contracts.mjs",
    "app/scripts/frameleaf-studio-rights.mjs",
    "app/studio/dependency-attribution.json",
    "app/studio/rights-approval.json",
    "app/studio/tools/qualification/fd36-kokoro/candidate.mjs",
    "app/studio/tools/qualification/fd36-kokoro/espeak-native.mjs",
    "app/studio/tools/qualification/fd36-kokoro/runtime.mjs",
    "espeak/share/espeak-ng-data/en_dict",
    "espeak/share/espeak-ng-data/intonations",
    "espeak/share/espeak-ng-data/lang/gmw/en",
    "espeak/share/espeak-ng-data/lang/gmw/en-US",
    "espeak/share/espeak-ng-data/phondata",
    "espeak/share/espeak-ng-data/phonindex",
    "espeak/share/espeak-ng-data/phontab",
    "espeak/source/COPYING",
    "espeak/source/COPYING.APACHE",
    "espeak/source/COPYING.BSD2",
    "espeak/source/COPYING.UCD",
];
const PINS: &[(&str, u64, &str)] = &[
    (
        "js/node_modules/@huggingface/transformers/package.json",
        2_694,
        "00c02ca357bf03c801f33c9a431c0169b99c1de1e14f2134cabc902cce53d4f3",
    ),
    (
        "js/node_modules/onnxruntime-node/package.json",
        1_678,
        "0956b483c9f285a2cbfff3cbb9b15540ed8e2b00523c2e39ed9d5aa0b10415ae",
    ),
    (
        "js/node_modules/kokoro-js/LICENSE",
        11_357,
        "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
    ),
    (
        "js/node_modules/kokoro-js/package.json",
        1_429,
        "20d193e8779551ecd99273509c3444315b5527e5aa04c6705507ece742af6d29",
    ),
    (
        "espeak/source/NOTICE.md",
        929,
        "8ceb607e3b2868cced148e07acbf7240fe31ede2062a6560c52b5ed259b13622",
    ),
    (
        "espeak/source/build-espeak-native.sh",
        2_760,
        "54b9ed8613d692389da461afe320cd48ec5fd050320bf282cc728c6b81fd5679",
    ),
    (
        "espeak/source/espeak-ng.tar.gz",
        16_341_184,
        "e6b84b52a87b3ad72885331bd942b2adecd70c384fa4ecfbe10aae7d9afd5e21",
    ),
    (
        "js/node_modules/kokoro-js/dist/kokoro.js",
        10_979,
        "31b1db2aa4a7411f55786900f0cbdd0351f1063859b107f9a99699a03b098b7d",
    ),
    (
        "js/node_modules/kokoro-js/voices/af_heart.bin",
        522_240,
        "d583ccff3cdca2f7fae535cb998ac07e9fcb90f09737b9a41fa2734ec44a8f0b",
    ),
    (
        "js/node_modules/kokoro-js/voices/af_bella.bin",
        522_240,
        "f69d836209b78eb8c66e75e3cda491e26ea838a3674257e9d4e5703cbaf55c8b",
    ),
    (
        "model/config.json",
        44,
        "df34b4f930b23447cd4dc410fabfb42eb3f24e803e6c3f97d618fb359380a36f",
    ),
    (
        "model/tokenizer.json",
        3_497,
        "77a02c8e164413299b4b4c403b14f8e0e1c1b727db4d46a09d6327b861060a34",
    ),
    (
        "model/tokenizer_config.json",
        113,
        "be1cb066d6ef6b074b3f15e6a6dd21ac88ff3cdaedf325f0aaed686c70f75d20",
    ),
    (
        "model/onnx/model_quantized.onnx",
        92_361_116,
        "fbae9257e1e05ffc727e951ef9b9c98418e6d79f1c9b6b13bd59f5c9028a1478",
    ),
];

/// Only call with the signed host inventory. The host verifier also checks every listed byte.
pub(super) fn verify_inventory(
    files: &BTreeMap<String, Artifact>,
    platform: &str,
    architecture: &str,
) -> Result<(), String> {
    if files
        .keys()
        .any(|name| !name.starts_with(ROOT) && name.to_ascii_lowercase().starts_with(ROOT))
    {
        return Err("host_voiceover_unqualified_artifact".into());
    }
    let names: Vec<&str> = files
        .keys()
        .filter_map(|name| name.strip_prefix(ROOT))
        .collect();
    if names.is_empty() {
        return Ok(());
    }
    if (platform, architecture) != ("macos", "aarch64") {
        return Err("host_voiceover_target_unqualified".into());
    }
    if REQUIRED_FILES
        .iter()
        .copied()
        .chain(["espeak/bin/espeak-ng"])
        .any(|name| {
            files
                .get(&format!("{ROOT}{name}"))
                .is_none_or(|file| file.bytes == 0)
        })
    {
        return Err("host_voiceover_component_missing".into());
    }
    for &(name, bytes, sha256) in PINS {
        if files
            .get(&format!("{ROOT}{name}"))
            .is_none_or(|artifact| artifact.bytes != bytes || artifact.sha256 != sha256)
        {
            return Err("host_voiceover_pin_mismatch".into());
        }
    }
    if names.iter().any(|name| {
        name.split('/')
            .any(|part| part.eq_ignore_ascii_case("phonemizer"))
            || ((name.to_ascii_lowercase().starts_with("model/")
                || name
                    .to_ascii_lowercase()
                    .starts_with("js/node_modules/kokoro-js/voices/"))
                && !PINS.iter().any(|pin| pin.0 == *name))
    }) {
        return Err("host_voiceover_unqualified_artifact".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> BTreeMap<String, Artifact> {
        let mut files = BTreeMap::new();
        for name in REQUIRED_FILES
            .iter()
            .copied()
            .chain(["espeak/bin/espeak-ng"])
        {
            files.insert(
                format!("{ROOT}{name}"),
                Artifact {
                    bytes: 1,
                    sha256: "a".repeat(64),
                },
            );
        }
        for &(name, bytes, sha256) in PINS {
            files.insert(
                format!("{ROOT}{name}"),
                Artifact {
                    bytes,
                    sha256: sha256.to_owned(),
                },
            );
        }
        files
    }

    #[test]
    fn candidate_is_optional_but_pinned_if_present() {
        assert!(verify_inventory(&BTreeMap::new(), "windows", "x86_64").is_ok());
        let mut files = fixture();
        assert!(verify_inventory(&files, "macos", "aarch64").is_ok());
        for (platform, arch) in [
            ("macos", "x86_64"),
            ("windows", "x86_64"),
            ("linux", "aarch64"),
        ] {
            assert_eq!(
                verify_inventory(&files, platform, arch).unwrap_err(),
                "host_voiceover_target_unqualified"
            );
        }
        files
            .get_mut(&format!("{ROOT}model/config.json"))
            .unwrap()
            .sha256 = "0".repeat(64);
        assert_eq!(
            verify_inventory(&files, "macos", "aarch64").unwrap_err(),
            "host_voiceover_pin_mismatch"
        );
    }

    #[test]
    fn candidate_refuses_opaque_phonemizer_and_tampered_source_notice() {
        let mut files = fixture();
        let legacy =
            format!("{ROOT}js/node_modules/kokoro-js/node_modules/phonemizer/dist/phonemizer.js");
        files.insert(
            legacy.clone(),
            Artifact {
                bytes: 1,
                sha256: "a".repeat(64),
            },
        );
        assert_eq!(
            verify_inventory(&files, "macos", "aarch64").unwrap_err(),
            "host_voiceover_unqualified_artifact"
        );
        files.remove(&legacy);
        files
            .get_mut(&format!("{ROOT}espeak/source/NOTICE.md"))
            .unwrap()
            .sha256 = "0".repeat(64);
        assert_eq!(
            verify_inventory(&files, "macos", "aarch64").unwrap_err(),
            "host_voiceover_pin_mismatch"
        );
    }
}
