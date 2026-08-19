//! Owns all live sessions. Enforces the concurrency limit and the
//! live-name uniqueness rule (spec §4.1: names are unique among *live*
//! sessions; an exited session releases its name).

use super::{Session, SessionId};
use crate::{HoldfastError, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

pub const DEFAULT_MAX_SESSIONS: usize = 8;
pub const DEFAULT_BUFFER_BYTES: usize = 1024 * 1024;

pub struct SessionRegistry {
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    max_sessions: usize,
}

impl SessionRegistry {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_SESSIONS)
    }

    /// Number of sessions whose child is still running.
    pub fn live_count(&self) -> usize {
        self.sessions
            .read()
            .values()
            .filter(|s| s.is_alive())
            .count()
    }

    /// Insert a session, enforcing the limit and name rules.
    pub fn insert(&self, session: Arc<Session>) -> Result<()> {
        // Both checks and the insert share one write lock. Taking a read
        // lock per check and a write lock to insert would let two
        // concurrent inserts each observe the same name as free.
        let mut map = self.sessions.write();
        if let Some(name) = session.name.as_deref() {
            let taken = map
                .values()
                .any(|s| s.is_alive() && s.name.as_deref() == Some(name));
            if taken {
                return Err(HoldfastError::NameTaken(name.to_string()));
            }
        }
        if map.values().filter(|s| s.is_alive()).count() >= self.max_sessions {
            return Err(HoldfastError::LimitReached(self.max_sessions));
        }
        map.insert(session.id.clone(), session);
        Ok(())
    }

    /// Resolve by session id, or by the name of a live session. Ids
    /// resolve whether or not the session is still running; names only
    /// resolve to live sessions, since an exited session releases its
    /// name and a later session may have taken it.
    pub fn get(&self, id_or_name: &str) -> Result<Arc<Session>> {
        let map = self.sessions.read();
        if let Some(s) = map.get(id_or_name) {
            return Ok(Arc::clone(s));
        }
        map.values()
            .find(|s| s.is_alive() && s.name.as_deref() == Some(id_or_name))
            .map(Arc::clone)
            .ok_or_else(|| HoldfastError::SessionNotFound(id_or_name.to_string()))
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.write().remove(id)
    }

    pub fn all(&self) -> Vec<Arc<Session>> {
        self.sessions.read().values().cloned().collect()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::MockPty;
    use crate::session::{new_session_id, Session};

    fn mock_session(name: Option<&str>) -> (Arc<Session>, Arc<MockPty>) {
        let pty = Arc::new(MockPty::new());
        let s = Session::new(
            new_session_id(),
            name.map(String::from),
            "bash".into(),
            vec![],
            Arc::clone(&pty) as Arc<dyn crate::pty::PtyBackend>,
            crate::session::SessionConfig::with_buffer_capacity(4096),
        );
        (s, pty)
    }

    #[test]
    fn session_ids_are_prefixed_and_unique() {
        let a = new_session_id();
        let b = new_session_id();
        assert!(a.starts_with("sess_"));
        assert_ne!(a, b);
    }

    #[test]
    fn insert_and_get_by_id() {
        let reg = SessionRegistry::with_defaults();
        let (s, _p) = mock_session(None);
        let id = s.id.clone();
        reg.insert(s).unwrap();
        assert_eq!(reg.get(&id).unwrap().id, id);
    }

    #[test]
    fn get_by_name_resolves_live_sessions() {
        let reg = SessionRegistry::with_defaults();
        let (s, _p) = mock_session(Some("build"));
        let id = s.id.clone();
        reg.insert(s).unwrap();
        assert_eq!(reg.get("build").unwrap().id, id);
    }

    #[test]
    fn duplicate_live_name_is_rejected() {
        let reg = SessionRegistry::with_defaults();
        let (a, _pa) = mock_session(Some("build"));
        let (b, _pb) = mock_session(Some("build"));
        reg.insert(a).unwrap();
        assert!(matches!(reg.insert(b), Err(HoldfastError::NameTaken(_))));
    }

    #[test]
    fn exited_session_releases_its_name() {
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(Some("build"));
        reg.insert(a).unwrap();
        pa.exit(0);
        let (b, _pb) = mock_session(Some("build"));
        reg.insert(b)
            .expect("name should be free once the holder exits");
    }

    #[test]
    fn exited_session_still_resolves_by_id() {
        // The agent must still be able to read the final output and exit
        // code of a session that has finished.
        let reg = SessionRegistry::with_defaults();
        let (a, pa) = mock_session(Some("build"));
        let id = a.id.clone();
        reg.insert(a).unwrap();
        pa.exit(3);
        assert_eq!(reg.get(&id).unwrap().id, id);
        assert!(matches!(
            reg.get("build"),
            Err(HoldfastError::SessionNotFound(_))
        ));
    }

    #[test]
    fn limit_counts_only_live_sessions() {
        let reg = SessionRegistry::new(2);
        let (a, pa) = mock_session(None);
        let (b, _pb) = mock_session(None);
        reg.insert(a).unwrap();
        reg.insert(b).unwrap();

        let (c, _pc) = mock_session(None);
        assert!(matches!(reg.insert(c), Err(HoldfastError::LimitReached(2))));

        pa.exit(0);
        let (d, _pd) = mock_session(None);
        reg.insert(d).expect("slot freed by the exited session");
    }

    #[test]
    fn missing_session_is_an_error() {
        let reg = SessionRegistry::with_defaults();
        assert!(matches!(
            reg.get("nope"),
            Err(HoldfastError::SessionNotFound(_))
        ));
    }
}
