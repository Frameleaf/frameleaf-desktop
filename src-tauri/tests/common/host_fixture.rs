use super::VerifiedHostRuntime;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

pub struct Fixture(pub PathBuf, pub Value, pub PathBuf);

impl Fixture {
    pub fn new() -> Self {
        let candidate = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-host-{}", Uuid::new_v4()));
        let root = candidate.join("payload");
        fs::create_dir_all(&root).unwrap();
        let paths = BTreeMap::from([
            ("node", "node"),
            ("server", "server/main.js"),
            ("postgres", "pg/postgres"),
            ("initdb", "pg/initdb"),
            ("pgDump", "pg/pg_dump"),
            ("pgRestore", "pg/pg_restore"),
            ("pgIsready", "pg/pg_isready"),
            ("pgChecksums", "pg/pg_checksums"),
            ("pgCtl", "pg/pg_ctl"),
            ("psql", "pg/psql"),
            ("createdb", "pg/createdb"),
            ("vector", "pg/vector"),
            ("hdr", "media/hdr"),
            ("ffmpeg", "media/ffmpeg"),
            ("ffprobe", "media/ffprobe"),
            ("exiftool", "media/exiftool"),
            ("rawRenderer", "raw/bin/darktable-cli"),
            ("rawDecoder", "raw/bin/dcraw_emu"),
            ("webIndex", "build/www/index.html"),
            ("studio", "studio/worker"),
            ("studioBrowser", "browser/chrome"),
            ("studioBrowserGuard", "studio/guard/studio-browser-guard"),
            ("corePlugin", "build/plugins/core/manifest.json"),
            ("mlManifest", "ml/manifest.json"),
            ("manager", "manager/app/build/main.js"),
            ("managerWebIndex", "manager/app/ui/dist/index.html"),
            ("backupEngine", "backup/restic"),
        ]);
        let mut files = serde_json::Map::new();
        for name in paths.values().copied().chain([
            "backup/LICENSE",
            "backup/component.json",
            "studio/engine-build.json",
            "studio/guard/studio-browser-guard.mjs",
            "studio/tools/bundled-worker-fonts.mjs",
            "studio/tools/render-worker-font-inputs.mjs",
            "studio/runtime/admission-font.json",
            "studio/runtime/admission-font.ttf",
            "build/geodata/geodata-date.txt",
            "build/geodata/cities500.txt",
            "build/geodata/admin1CodesASCII.txt",
            "build/geodata/admin2Codes.txt",
            "build/geodata/countryInfo.txt",
            "build/geodata/ne_10m_admin_0_countries.geojson",
            "build/geodata/landmarks.ndjson.gz",
            "manager/app/release-worker.cjs",
            "manager/app/media-copy.cjs",
            "manager/.github/frameleaf-release.cjs",
            "manager/.github/verify-release-bundle.cjs",
            "manager/cosign.pub",
            "manager/component.json",
            "manager/package.json",
            "manager/LICENSE",
            "manager/node_modules/@nestjs/common/package.json",
            "manager/node_modules/@nestjs/core/package.json",
            "manager/node_modules/@nestjs/platform-express/package.json",
            "manager/node_modules/express/package.json",
            "manager/node_modules/js-yaml/package.json",
            "manager/node_modules/reflect-metadata/package.json",
            "manager/node_modules/rxjs/package.json",
            "manager/node_modules/zod/package.json",
        ]) {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"fixture").unwrap();
            files.insert(
                name.into(),
                json!({"bytes":7,"sha256":format!("{:x}",Sha256::digest(b"fixture"))}),
            );
        }
        let spec = json!({"schemaVersion":1,"protocolVersion":2,"epoch":1,
            "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "sourceRevision":"a".repeat(40),"nodeVersion":"26.11.1",
            "postgresVersion":"19beta4","vectorVersion":"0.8.7","certified":false,
            "entryPoints":paths,"files":files});
        Self(root, spec, candidate)
    }
    pub fn verify(&self) -> Result<VerifiedHostRuntime, String> {
        let key = SigningKey::from_bytes(&[42; 32]);
        let raw = serde_json::to_vec(&self.1).unwrap();
        VerifiedHostRuntime::verify(
            &self.0,
            &raw,
            &key.sign(&raw).to_bytes(),
            &[key.verifying_key()],
            1,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.2);
    }
}
