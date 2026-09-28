//! drivers.lock.yaml must agree with the versions pinned into the runner image.

use std::path::Path;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn drivers_lock_matches_image_pins_and_registry() {
    let lock: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(root().join("drivers.lock.yaml")).unwrap()).unwrap();
    let pkg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root().join("images/runner/package.json")).unwrap()).unwrap();
    let pkg_lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root().join("images/runner/package-lock.json")).unwrap())
            .unwrap();
    let deps = pkg["dependencies"].as_object().unwrap();
    let allowed =
        ["compatible", "compatible-unauthenticated", "contract-verified-with-fake", "candidate", "incompatible"];
    let drivers = lock["drivers"].as_sequence().unwrap();
    let names: Vec<&str> = drivers.iter().map(|d| d["driver"].as_str().unwrap()).collect();
    for known in acp_runner_drivers::KNOWN_DRIVERS {
        assert!(names.contains(known), "driver {known} missing from drivers.lock.yaml");
    }
    let profiles: Vec<&serde_yaml::Value> =
        drivers.iter().filter_map(|d| d["profiles"].as_sequence()).flatten().collect();
    for p in &profiles {
        for f in ["launch", "report"] {
            let path = p[f].as_str().unwrap();
            assert!(root().join(path).exists(), "{path} referenced by drivers.lock.yaml is missing");
        }
    }
    for d in drivers.iter().chain(profiles.iter().copied()) {
        let status = d["status"].as_str().unwrap();
        assert!(allowed.contains(&status), "unknown status {status}");
        for part in ["cli", "adapter"] {
            let entry = &d[part];
            if entry.is_null() || entry["source"].as_str() == Some("workspace") {
                continue;
            }
            let name = entry["package"].as_str().unwrap();
            let version = entry["version"].as_str().unwrap();
            assert_eq!(
                deps.get(name).and_then(|v| v.as_str()),
                Some(version),
                "{name}: drivers.lock.yaml says {version}, images/runner/package.json disagrees"
            );
            let locked = &pkg_lock["packages"][format!("node_modules/{name}")]["version"];
            assert_eq!(locked.as_str(), Some(version), "{name}: package-lock.json not regenerated");
        }
    }
    // exact pins only (no ranges) so the image is reproducible
    for (name, v) in deps {
        let v = v.as_str().unwrap();
        assert!(v.chars().all(|c| c.is_ascii_digit() || c == '.'), "{name} must be pinned exactly, got {v}");
    }
}
