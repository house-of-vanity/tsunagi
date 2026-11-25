//! Exit offers may need the local user's approval. The dialog belongs to the
//! initiating client, outside the daemon's IPC deadline and network actors.
use super::{EXCHANGE_TIMEOUT, Error, Path, Request, Response, Result, exchange};
use crate::state::Ipv4Range;
use serde::{Deserialize, Serialize};

/// Result of applying the local exit settings on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitOfferOutcome {
    /// Current setting after applying the requested change.
    Set(bool),
    /// macOS denied the host operation for this local overlay range.
    NeedsAuthorization {
        /// Locally selected overlay range.
        range: Ipv4Range,
        /// Owner of the running agent.
        agent_uid: u32,
    },
}

/// Offers the running agent as an exit in one network, or withdraws it.
pub async fn set_exit_offer(
    path: impl AsRef<Path>,
    network_id: &str,
    enabled: bool,
) -> Result<bool> {
    #[cfg(target_os = "macos")]
    let authorize = |path: &Path, range, uid| {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let socket = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !socket.file_type().is_socket() || uid == 0 || socket.uid() != uid {
            return Err("The local control socket does not belong to the account requesting exit authorization".into());
        }
        crate::overlay::hostrules::authorize_macos_exit(range, uid)
    };
    #[cfg(not(target_os = "macos"))]
    let authorize =
        |_: &Path, _, _| Err("macOS exit authorization is unavailable on this platform".into());
    apply(path.as_ref(), network_id, enabled, authorize).await
}

async fn apply(
    path: &Path,
    id: &str,
    enabled: bool,
    authorize: impl FnOnce(&Path, Ipv4Range, u32) -> std::result::Result<(), String> + Send + 'static,
) -> Result<bool> {
    let request = |choice| Request::SetExitOffer {
        network_id: id.to_owned(),
        enabled: choice,
    };
    let decode = |answer| match answer {
        Response::ExitOffer(outcome) => Ok(outcome),
        Response::Error(message) => Err(Error::Storage(message)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    };
    let result = decode(exchange(path, &request(Some(enabled)), EXCHANGE_TIMEOUT).await?)?;
    match result {
        ExitOfferOutcome::Set(on) => Ok(on),
        ExitOfferOutcome::NeedsAuthorization { range, agent_uid } if enabled => {
            let path_owned = path.to_owned();
            tokio::task::spawn_blocking(move || authorize(&path_owned, range, agent_uid))
                .await
                .map_err(|err| {
                    Error::Storage(format!("could not finish macOS authorization: {err}"))
                })?
                .map_err(Error::Storage)?;
            // Reconcile the current settings. A different client may have withdrawn
            // its offer while the system was waiting for the user to respond.
            match decode(exchange(path, &request(None), EXCHANGE_TIMEOUT).await?)? {
                ExitOfferOutcome::Set(on) => Ok(on),
                ExitOfferOutcome::NeedsAuthorization { .. } => Err(Error::Storage(
                    "macOS still denies the exit settings after authorization".into(),
                )),
            }
        }
        ExitOfferOutcome::NeedsAuthorization { .. } => Err(Error::Storage(
            "unexpected authorization request while withdrawing an exit".into(),
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::ipc::{ControlSocket, ControlSocketAccess, ReportSource, StatusReport};
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct Source {
        calls: Mutex<Vec<Option<bool>>>,
        answers: Mutex<VecDeque<ExitOfferOutcome>>,
    }

    impl ReportSource for Source {
        fn report(&self) -> crate::BoxFuture<'_, StatusReport> {
            Box::pin(async { StatusReport::default() })
        }

        fn set_exit_offer(
            &self,
            id: String,
            change: Option<bool>,
        ) -> crate::BoxFuture<'_, std::result::Result<ExitOfferOutcome, String>> {
            assert_eq!(id, "lab");
            self.calls.lock().unwrap().push(change);
            let answer = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .ok_or("unexpected reapply".to_owned());
            Box::pin(async move { answer })
        }
    }

    #[tokio::test]
    async fn prompt_only_on_denial_and_retry_the_current_plan_once() {
        let subnet: Ipv4Range = "10.2.3.0/24".parse().unwrap();
        let need = ExitOfferOutcome::NeedsAuthorization {
            range: subnet,
            agent_uid: 501,
        };
        let on = ExitOfferOutcome::Set(true);
        let off = ExitOfferOutcome::Set(false);
        for (answers, enabled, grant, prompts, result) in [
            (vec![on], true, true, 0, Some(true)),
            (vec![off], false, true, 0, Some(false)),
            (vec![need, on], true, true, 1, Some(true)),
            (vec![need, off], true, true, 1, Some(false)),
            (vec![need, need], true, true, 1, None),
            (vec![need], true, false, 1, None),
            (vec![need], false, true, 0, None),
        ] {
            let requests = answers.len();
            let source = Arc::new(Source {
                calls: Default::default(),
                answers: Mutex::new(answers.into()),
            });
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("agent.sock");
            let server = ControlSocket::bind(&path, source.clone(), ControlSocketAccess::Private)
                .await
                .unwrap();
            let approvals = Arc::new(AtomicUsize::new(0));
            let seen = approvals.clone();
            let actual = apply(&path, "lab", enabled, move |_, range, uid| {
                seen.fetch_add(1, Ordering::Relaxed);
                assert_eq!((range, uid), (subnet, 501));
                if grant {
                    Ok(())
                } else {
                    Err("cancelled".into())
                }
            })
            .await;
            assert_eq!(actual.ok(), result);
            assert_eq!(approvals.load(Ordering::Relaxed), prompts);
            let expected = if requests == 1 {
                vec![Some(enabled)]
            } else {
                vec![Some(enabled), None]
            };
            assert_eq!(*source.calls.lock().unwrap(), expected);
            server.shutdown().await;
        }
    }
}
