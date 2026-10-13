//! Takes the API key horizon derives in project and org key modes.
//!
//! Without a key in `PDP_API_KEY`, horizon derives the environment's key from the control plane.
//! The PDP names a file in a directory only its user can enter, horizon writes the key there on
//! every start, and the PDP reads it back every second.

use crate::api_key::{ApiKey, CurrentApiKey, InvalidApiKey};
use log::{debug, info, warn};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::time::{Instant, MissedTickBehavior};

/// The variable that names the file horizon writes the key it derives into.
pub const FILE_ENV: &str = "PDP_API_KEY_HANDOFF_FILE";

const FILE_NAME: &str = "api-key";
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const WARN_AFTER: Duration = Duration::from_secs(60);

/// Why the handoff file gave no key.
#[derive(Debug, Error)]
enum NoKey {
    #[error("cannot read the file: {0}")]
    Unreadable(#[from] io::Error),
    #[error("{0}")]
    Invalid(#[from] InvalidApiKey),
}

/// Creates the directory horizon writes the key into and starts taking the key from there.
/// Returns the absolute path of the file horizon writes.
///
/// The task that reads the file owns the directory. It runs until the runtime shuts down, which
/// drops the directory and removes it.
pub fn start(current: CurrentApiKey) -> io::Result<PathBuf> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("pdp-api-key-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir()?;
    let file = std::path::absolute(dir.path().join(FILE_NAME))?;

    let watched = file.clone();
    tokio::spawn(async move {
        // Moved into the task so the directory lives exactly as long as the task does
        let _dir = dir;
        watch(&watched, &current, POLL_INTERVAL, WARN_AFTER).await;
    });
    Ok(file)
}

/// Reads the handoff file every `poll_interval`, forever.
async fn watch(
    path: &Path,
    current: &CurrentApiKey,
    poll_interval: Duration,
    warn_after: Duration,
) {
    let started = Instant::now();
    let mut next_warning = started + warn_after;
    let mut ticks = tokio::time::interval(poll_interval);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let Err(reason) = check(path, current).await else {
            continue;
        };
        debug!("No API key from horizon in {}: {reason}", path.display());
        if current.get().is_none() && Instant::now() >= next_warning {
            warn!(
                "Horizon has not handed over an API key in the {}s since startup ({reason}); \
                 requests that need the key get 503 until it does",
                started.elapsed().as_secs()
            );
            next_warning += warn_after;
        }
    }
}

/// Makes the key in the handoff file the current key, if the file holds one.
async fn check(path: &Path, current: &CurrentApiKey) -> Result<(), NoKey> {
    let contents = tokio::fs::read_to_string(path).await?;
    let key = ApiKey::new(&contents)?;
    if current.replace(key) {
        info!("Loaded the API key from horizon");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_key::{ApiKeySource, PLACEHOLDER};
    use crate::test_utils::{LogCapture, TestFixture};
    use http::{header::AUTHORIZATION, Method, StatusCode};
    use serde_json::json;
    use wiremock::{matchers, Mock, ResponseTemplate};

    const DERIVED: &str = "permit_key_derived";
    const ROTATED: &str = "permit_key_rotated";
    const FAST_POLL: Duration = Duration::from_millis(10);

    /// Writes `contents` the way horizon does: to a sibling file renamed over the target.
    fn hand_over(path: &Path, contents: &str) {
        let staged = path.with_extension("tmp");
        std::fs::write(&staged, contents).expect("Failed to write the staged key file");
        std::fs::rename(&staged, path).expect("Failed to move the key file into place");
    }

    async fn wait_for_key(current: &CurrentApiKey, expected: &str) {
        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            while current.get().is_none_or(|key| key.as_str() != expected) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "the PDP did not take the key horizon handed over"
        );
    }

    fn current_key(current: &CurrentApiKey) -> Option<String> {
        current.get().map(|key| key.as_str().to_string())
    }

    #[tokio::test]
    async fn test_key_in_the_file_becomes_the_current_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(None);

        hand_over(&path, DERIVED);
        check(&path, &current).await.unwrap();

        assert_eq!(current_key(&current).as_deref(), Some(DERIVED));
    }

    #[tokio::test]
    async fn test_missing_file_leaves_the_pdp_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let current = CurrentApiKey::new(None);

        let result = check(&dir.path().join(FILE_NAME), &current).await;

        let Err(NoKey::Unreadable(err)) = result else {
            panic!("expected an unreadable file, got {result:?}");
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(current.get().is_none());
    }

    #[tokio::test]
    async fn test_file_without_a_key_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);

        for (contents, reason) in [
            ("", InvalidApiKey::Empty),
            (PLACEHOLDER, InvalidApiKey::Placeholder),
            ("permit_key\n", InvalidApiKey::NotHeaderSafe),
        ] {
            let current = CurrentApiKey::new(None);
            hand_over(&path, contents);

            let result = check(&path, &current).await;

            let Err(NoKey::Invalid(invalid)) = result else {
                panic!("expected {reason:?} for {contents:?}, got {result:?}");
            };
            assert_eq!(invalid, reason, "{contents:?}");
            assert!(current.get().is_none(), "{contents:?}");
        }
    }

    #[tokio::test]
    async fn test_file_without_a_key_keeps_the_key_already_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(None);
        hand_over(&path, DERIVED);
        check(&path, &current).await.unwrap();

        for contents in ["", PLACEHOLDER] {
            hand_over(&path, contents);
            assert!(check(&path, &current).await.is_err());
            assert_eq!(current_key(&current).as_deref(), Some(DERIVED));
        }
    }

    #[tokio::test]
    async fn test_unreadable_file_leaves_the_pdp_without_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, b"permit_key_\xff").unwrap();
        let current = CurrentApiKey::new(None);

        let result = check(&path, &current).await;

        let Err(NoKey::Unreadable(err)) = result else {
            panic!("expected an unreadable file, got {result:?}");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(current.get().is_none());
    }

    #[tokio::test]
    async fn test_watch_follows_the_key_horizon_hands_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(None);
        let watcher = tokio::spawn({
            let (path, current) = (path.clone(), current.clone());
            async move { watch(&path, &current, FAST_POLL, WARN_AFTER).await }
        });

        hand_over(&path, DERIVED);
        wait_for_key(&current, DERIVED).await;
        hand_over(&path, ROTATED);
        wait_for_key(&current, ROTATED).await;

        watcher.abort();
    }

    /// The key never reaches a log line: not its value, and not at any level.
    #[tokio::test]
    async fn test_loading_a_key_logs_that_it_did_but_not_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(None);
        hand_over(&path, DERIVED);
        let logs = LogCapture::start();

        check(&path, &current).await.unwrap();

        let lines = logs.lines();
        assert_eq!(lines, ["INFO Loaded the API key from horizon"]);
    }

    /// Missing the file is routine while horizon starts, so it is a debug line each time; only a
    /// long wait without a key warns, and then once per wait rather than on every look.
    #[tokio::test]
    async fn test_warns_when_horizon_does_not_hand_over_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(None);
        let logs = LogCapture::start();

        let watching = watch(
            &path,
            &current,
            Duration::from_millis(5),
            Duration::from_millis(50),
        );
        let _ = tokio::time::timeout(Duration::from_millis(200), watching).await;

        let lines = logs.lines();
        let first_warning = lines.iter().position(|line| line.starts_with("WARN"));
        let warnings = lines.iter().filter(|line| line.starts_with("WARN")).count();
        assert!(
            lines[0].starts_with("DEBUG No API key from horizon"),
            "{lines:?}"
        );
        assert!(
            first_warning.is_some_and(|index| index >= 2),
            "expected a warning only after a wait without a key: {lines:?}"
        );
        assert!(
            warnings <= 5,
            "expected one warning per 50ms wait: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("WARN")
                    && line.contains("has not handed over an API key")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn test_no_warning_once_there_is_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let current = CurrentApiKey::new(Some(ApiKey::new(DERIVED).unwrap()));
        let logs = LogCapture::start();

        let watching = watch(&path, &current, FAST_POLL, Duration::ZERO);
        let _ = tokio::time::timeout(Duration::from_millis(50), watching).await;

        let lines = logs.lines();
        assert!(
            lines.iter().all(|line| !line.starts_with("WARN")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn test_start_hands_over_through_a_private_directory() {
        let current = CurrentApiKey::new(None);

        let path = start(current.clone()).unwrap();

        assert!(path.is_absolute(), "{path:?}");
        assert_eq!(path.file_name().unwrap(), FILE_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::fs::metadata(path.parent().unwrap()).unwrap();
            assert_eq!(dir.permissions().mode() & 0o777, 0o700);
        }
        hand_over(&path, DERIVED);
        wait_for_key(&current, DERIVED).await;
    }

    /// The whole app, started without a key of its own: until horizon hands one over it answers
    /// 503 on protected routes and still serves health and the API docs; afterwards it accepts the
    /// key horizon derived, presents it to OPA and horizon, and follows a rotation.
    #[tokio::test]
    async fn test_app_uses_the_key_horizon_hands_over() {
        let fixture = TestFixture::with_config_modifier(|config| {
            config.api_key = ApiKeySource::Horizon;
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let watcher = tokio::spawn({
            let (path, current) = (path.clone(), fixture.state.api_key.clone());
            async move { watch(&path, &current, FAST_POLL, WARN_AFTER).await }
        });
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/data/permit/root"))
            .and(matchers::header(AUTHORIZATION, format!("Bearer {DERIVED}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": { "allow": true }
            })))
            .expect(1)
            .mount(&fixture.opa_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/legacy"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&fixture.horizon_mock)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/openapi.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"openapi": "3.1.0"})))
            .expect(1)
            .mount(&fixture.horizon_mock)
            .await;
        let allowed_query = json!({
            "user": {"key": "test-user", "attributes": {}},
            "action": "read",
            "resource": {
                "type": "document",
                "key": "test-resource",
                "tenant": "test-tenant",
                "attributes": {},
                "context": {}
            },
            "context": {}
        });
        let send = |method: Method, uri: &str, bearer: &str| {
            let request = http::Request::builder()
                .method(method)
                .uri(uri)
                .header(AUTHORIZATION, format!("Bearer {bearer}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(allowed_query.to_string()))
                .unwrap();
            fixture.send(request)
        };

        for bearer in [PLACEHOLDER, DERIVED] {
            let response = send(Method::POST, "/allowed", bearer).await;
            response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.text(), crate::api_key::NO_KEY_YET);
        }
        let response = fixture.get("/openapi.json").await;
        response.assert_ok();
        let response = fixture.get("/health").await;
        assert!(response.json()["components"]["opa"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("no API key yet")));

        hand_over(&path, DERIVED);
        wait_for_key(&fixture.state.api_key, DERIVED).await;

        send(Method::POST, "/allowed", PLACEHOLDER)
            .await
            .assert_status(StatusCode::FORBIDDEN);
        send(Method::POST, "/allowed", DERIVED).await.assert_ok();
        send(Method::GET, "/legacy", DERIVED).await.assert_ok();

        hand_over(&path, ROTATED);
        wait_for_key(&fixture.state.api_key, ROTATED).await;

        send(Method::GET, "/legacy", DERIVED)
            .await
            .assert_status(StatusCode::FORBIDDEN);
        send(Method::GET, "/legacy", ROTATED).await.assert_ok();

        fixture.opa_mock.verify().await;
        fixture.horizon_mock.verify().await;
        let horizon_requests = fixture.horizon_mock.received_requests().await.unwrap();
        let presented: Vec<_> = horizon_requests
            .iter()
            .map(|request| {
                let path = request.url.path().to_string();
                let auth: Vec<_> = request.headers.get_all(AUTHORIZATION).iter().collect();
                (
                    path,
                    auth.iter()
                        .map(|v| v.to_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            presented,
            [
                ("/openapi.json".to_string(), vec![]),
                ("/healthy".to_string(), vec![]),
                ("/legacy".to_string(), vec![format!("Bearer {DERIVED}")]),
                ("/legacy".to_string(), vec![format!("Bearer {ROTATED}")]),
            ]
        );

        watcher.abort();
    }
}
