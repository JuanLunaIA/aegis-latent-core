// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Lock-free concurrent session store backed by DashMap.
//!
//! Replaces Python's `OrderedDict + threading.RLock` session manager.
//! DashMap uses per-shard RwLock (64 shards by default), reducing contention
//! from a global lock to 1/64 probability of lock collision under uniform load.
//!
//! LRU eviction: retained via timestamp comparison on capacity overflow
//! (O(n) scan, amortised O(1) under steady state).

use dashmap::DashMap;
use pyo3::prelude::*;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone)]
struct SessionEntry {
    last_seen: u64,
    request_count: u64,
}

/// Concurrent session registry with LRU eviction.
#[pyclass]
pub struct RustSessionStore {
    sessions: Arc<DashMap<String, SessionEntry>>,
    max_sessions: usize,
    evict_after_secs: u64,
    total_evictions: Arc<AtomicU64>,
}

#[pymethods]
impl RustSessionStore {
    #[new]
    #[pyo3(signature = (max_sessions = 4096, evict_after_secs = 3600))]
    pub fn new(max_sessions: usize, evict_after_secs: u64) -> Self {
        RustSessionStore {
            sessions: Arc::new(DashMap::with_capacity_and_shard_amount(max_sessions, 64)),
            max_sessions,
            evict_after_secs,
            total_evictions: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record a request for `session_id`. Returns `true` if this is a new session.
    pub fn touch(&self, session_id: &str) -> bool {
        let now = now_secs();
        let is_new = !self.sessions.contains_key(session_id);

        if is_new && self.sessions.len() >= self.max_sessions {
            self.evict_oldest_entry();
        }

        self.sessions
            .entry(session_id.to_string())
            .and_modify(|e| {
                e.last_seen = now;
                e.request_count += 1;
            })
            .or_insert(SessionEntry {
                last_seen: now,
                request_count: 1,
            });

        is_new
    }

    pub fn exists(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub fn request_count(&self, session_id: &str) -> u64 {
        self.sessions
            .get(session_id)
            .map(|e| e.request_count)
            .unwrap_or(0)
    }

    pub fn remove(&self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Evict sessions that have been inactive longer than `evict_after_secs`.
    /// Returns the number of evicted sessions.
    pub fn evict_stale(&self) -> usize {
        let cutoff = now_secs().saturating_sub(self.evict_after_secs);
        let before = self.sessions.len();
        self.sessions.retain(|_, v| v.last_seen > cutoff);
        let evicted = before.saturating_sub(self.sessions.len());
        self.total_evictions
            .fetch_add(evicted as u64, Ordering::Relaxed);
        evicted
    }

    pub fn total_evictions(&self) -> u64 {
        self.total_evictions.load(Ordering::Relaxed)
    }

    /// Age of the oldest session in seconds, or 0 if empty.
    pub fn oldest_session_age_secs(&self) -> u64 {
        let now = now_secs();
        self.sessions
            .iter()
            .map(|e| now.saturating_sub(e.last_seen))
            .max()
            .unwrap_or(0)
    }

    fn evict_oldest_entry(&self) {
        let oldest_key = self
            .sessions
            .iter()
            .min_by_key(|e| e.last_seen)
            .map(|e| e.key().clone());
        if let Some(key) = oldest_key {
            if self.sessions.remove(&key).is_some() {
                self.total_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_detected() {
        let store = RustSessionStore::new(100, 3600);
        assert!(store.touch("s1"));
        assert!(!store.touch("s1")); // second call: not new
    }

    #[test]
    fn request_count_increments() {
        let store = RustSessionStore::new(100, 3600);
        store.touch("s1");
        store.touch("s1");
        store.touch("s1");
        assert_eq!(store.request_count("s1"), 3);
    }

    #[test]
    fn evict_on_capacity() {
        let store = RustSessionStore::new(2, 3600);
        store.touch("a");
        store.touch("b");
        store.touch("c"); // triggers eviction of oldest
        assert_eq!(store.session_count(), 2);
    }
}
