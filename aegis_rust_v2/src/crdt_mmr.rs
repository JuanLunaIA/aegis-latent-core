// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Causal-Merkle CRDT — a join-semilattice over domain-separated Merkle
//! Mountain Ranges.
//!
//! # What this is for
//!
//! Each Aegis replica owns a private WAL and therefore a private chain; there
//! is no cross-replica ordering (see `DOC-01 §8`). This module provides the
//! data structure a gossip layer would need to reconcile those chains without
//! a leader, a lock, or a consensus round: replicas append locally, exchange
//! leaf sets, and every replica computes the same root.
//!
//! # What this is NOT
//!
//! This is an accumulator, not a deployment. It is **not wired into the
//! ledger**, there is no gossip transport, and it establishes nothing about
//! Byzantine resistance: `join` reconciles replicas that disagree about
//! *ordering*, not replicas that *lie*. A replica that fabricates leaves
//! contributes them to the merged root like any other. Cross-replica global
//! ordering remains open work.
//!
//! # Ordering, and why the obvious implementation is wrong
//!
//! Vector clocks give a *partial* order: concurrent events are incomparable.
//! Sorting by that partial order — comparing clocks and falling back to the
//! replica id when they are incomparable — does not yield a total order, and
//! the comparator is not transitive. `sort_by` with a non-transitive
//! comparator produces an order that depends on the input permutation, which
//! destroys commutativity and associativity: the two properties the whole
//! construction exists to provide.
//!
//! This implementation sorts by an explicit **total order** that extends
//! causality: the scalar clock sum first, then replica id, then that
//! replica's own sequence, then the leaf digest. The first key is what makes
//! it sound — if `a` causally precedes `b` then `a`'s clock is componentwise
//! ≤ `b`'s and differs somewhere, so `sum(a) < sum(b)`. Causally ordered
//! events therefore never invert, while concurrent events are broken by keys
//! that are identical on every replica. The result is deterministic
//! regardless of the order leaves arrive in.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Domain tag for a leaf digest. Matches `aegis-mmr-inclusion-v2`.
const DOMAIN_LEAF: u8 = 0x00;
/// Domain tag for an interior node. Matches `aegis-mmr-inclusion-v2`.
const DOMAIN_NODE: u8 = 0x01;
/// Domain tag for peak bagging. Matches `aegis-mmr-inclusion-v2`.
const DOMAIN_ROOT: u8 = 0x02;

/// A per-replica monotonic counter map.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VectorClock {
    clock: BTreeMap<u32, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self {
            clock: BTreeMap::new(),
        }
    }

    /// Advance this replica's own counter.
    ///
    /// Saturating rather than wrapping: a wrapped counter would silently
    /// reorder history, and a clock pinned at `u64::MAX` after 2^64 local
    /// appends is the safer failure.
    pub fn tick(&mut self, replica_id: u32) {
        let entry = self.clock.entry(replica_id).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Pointwise maximum — the join on the clock lattice.
    pub fn merge(&mut self, other: &VectorClock) {
        for (&replica, &seq) in &other.clock {
            let current = self.clock.entry(replica).or_insert(0);
            *current = (*current).max(seq);
        }
    }

    pub fn get(&self, replica_id: u32) -> u64 {
        self.clock.get(&replica_id).copied().unwrap_or(0)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&u32, &u64)> {
        self.clock.iter()
    }

    /// Scalar linearization: the sum of every counter.
    ///
    /// Saturating, so a clock near the counter ceiling degrades to an equal
    /// sum and is broken by the lower-order keys rather than wrapping into a
    /// smaller value and inverting causal order.
    pub fn scalar(&self) -> u64 {
        self.clock
            .values()
            .fold(0u64, |acc, &v| acc.saturating_add(v))
    }
}

impl PartialOrd for VectorClock {
    /// Causal precedence. `None` means the two events are concurrent, which
    /// is a real answer, not a failure.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut greater = false;
        let mut less = false;

        let keys: BTreeSet<u32> = self
            .clock
            .keys()
            .chain(other.clock.keys())
            .copied()
            .collect();

        for key in keys {
            let a = self.get(key);
            let b = other.get(key);
            if a > b {
                greater = true;
            }
            if a < b {
                less = true;
            }
            if greater && less {
                return None;
            }
        }

        match (greater, less) {
            (true, false) => Some(Ordering::Greater),
            (false, true) => Some(Ordering::Less),
            (false, false) => Some(Ordering::Equal),
            (true, true) => None,
        }
    }
}

/// One appended record, carrying the causal context it was created in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalLeaf {
    pub clock: VectorClock,
    pub replica_id: u32,
    pub payload_hash: [u8; 32],
}

impl CausalLeaf {
    /// Domain-separated digest over the replica, its clock, and the payload.
    ///
    /// The clock is length-prefixed so that two different clocks cannot
    /// serialise to the same byte string — without it, `{1:2}` and `{1:2,
    /// 2:0}` would be distinguishable only by length, and concatenating
    /// fixed-width entries would leave the boundary ambiguous against a
    /// following field.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_LEAF]);
        hasher.update(self.replica_id.to_be_bytes());
        hasher.update((self.clock.clock.len() as u64).to_be_bytes());
        for (&replica, &seq) in &self.clock.clock {
            hasher.update(replica.to_be_bytes());
            hasher.update(seq.to_be_bytes());
        }
        hasher.update(self.payload_hash);
        hasher.finalize().into()
    }

    /// The total-order sort key described in the module docs.
    fn sort_key(&self) -> (u64, u32, u64, [u8; 32]) {
        (
            self.clock.scalar(),
            self.replica_id,
            self.clock.get(self.replica_id),
            self.digest(),
        )
    }
}

/// An MMR whose leaves carry vector clocks, forming a join-semilattice.
#[derive(Clone, Debug)]
pub struct CausalMmr {
    replica_id: u32,
    clock: VectorClock,
    leaves: Vec<CausalLeaf>,
    peaks: Vec<[u8; 32]>,
}

impl CausalMmr {
    pub fn new(replica_id: u32) -> Self {
        Self {
            replica_id,
            clock: VectorClock::new(),
            leaves: Vec::new(),
            peaks: Vec::new(),
        }
    }

    pub fn replica_id(&self) -> u32 {
        self.replica_id
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn clock(&self) -> &VectorClock {
        &self.clock
    }

    pub fn peaks(&self) -> &[[u8; 32]] {
        &self.peaks
    }

    /// Append a payload under this replica's next clock value.
    pub fn append(&mut self, payload: &[u8]) -> [u8; 32] {
        let payload_hash: [u8; 32] = Sha256::digest(payload).into();
        self.clock.tick(self.replica_id);

        let leaf = CausalLeaf {
            clock: self.clock.clone(),
            replica_id: self.replica_id,
            payload_hash,
        };
        let digest = leaf.digest();
        self.leaves.push(leaf);
        Self::carry(&mut self.peaks, self.leaves.len(), digest);
        self.root()
    }

    /// Binary carry propagation: after appending the n-th leaf, merge once
    /// per trailing zero bit of n.
    fn carry(peaks: &mut Vec<[u8; 32]>, leaf_count: usize, mut edge: [u8; 32]) {
        let mut count = leaf_count;
        while count & 1 == 0 {
            let Some(left) = peaks.pop() else {
                break;
            };
            let mut hasher = Sha256::new();
            hasher.update([DOMAIN_NODE]);
            hasher.update(left);
            hasher.update(edge);
            edge = hasher.finalize().into();
            count >>= 1;
        }
        peaks.push(edge);
    }

    /// Bag the peaks into a single root, tallest first.
    ///
    /// The carry above leaves `peaks` in descending height already, so this
    /// consumes them in natural order to match the `aegis-mmr-inclusion-v2`
    /// convention. An empty range hashes the tag alone rather than returning
    /// zeroes, so "no leaves" is a value in the digest space rather than a
    /// sentinel any payload could also produce.
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_ROOT]);
        for peak in &self.peaks {
            hasher.update(peak);
        }
        hasher.finalize().into()
    }

    /// The join: `A ⊔ B`.
    ///
    /// Deduplicates by leaf digest, sorts by the total order, and rebuilds the
    /// accumulator. Because both steps depend only on the *set* of leaves and
    /// never on their arrival order, the result is identical for any input
    /// permutation — which is what makes the operation commutative and
    /// associative rather than merely convergent in practice.
    pub fn join(&self, other: &Self) -> Self {
        let mut merged_clock = self.clock.clone();
        merged_clock.merge(&other.clock);

        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut leaves: Vec<CausalLeaf> = Vec::with_capacity(self.leaves.len() + other.leaves.len());
        for leaf in self.leaves.iter().chain(other.leaves.iter()) {
            if seen.insert(leaf.digest()) {
                leaves.push(leaf.clone());
            }
        }
        leaves.sort_by_key(|leaf| leaf.sort_key());

        let mut merged = CausalMmr {
            replica_id: self.replica_id,
            clock: merged_clock,
            leaves: Vec::with_capacity(leaves.len()),
            peaks: Vec::new(),
        };
        for leaf in leaves {
            let digest = leaf.digest();
            merged.leaves.push(leaf);
            Self::carry(&mut merged.peaks, merged.leaves.len(), digest);
        }
        merged
    }
}

// ── Wire encoding ───────────────────────────────────────────────────────
//
// `join` is in-process; a gossip layer has to move a replica's leaf set over a
// socket, so the state needs a byte form. Three properties matter, and all
// three are about the decoder rather than the encoder, because the decoder is
// the half that faces a peer who may not be friendly.
//
// **Canonical.** Clock entries are written in ascending replica order and the
// decoder *rejects* any other order, so one state has exactly one encoding.
// Without that, a peer could re-order entries to produce a second byte string
// for the same leaf set, and any digest taken over the encoding would disagree
// with itself.
//
// **Bounded.** Counts are checked against explicit ceilings before anything is
// allocated. A length-prefixed format whose prefix is trusted is an
// out-of-memory primitive: `u64::MAX` leaves would ask for a 68-exabyte
// `Vec` on the strength of eight bytes from the network.
//
// **Total.** Every read is bounds-checked and every failure is a `Result`.
// This decoder must never panic: it runs behind a PyO3 boundary, where an
// unwind aborts the interpreter rather than raising.

/// Magic and format version. A change to the layout must change the trailing
/// byte, so an old peer rejects a new encoding rather than misreading it.
const STATE_MAGIC: &[u8; 8] = b"AEGCRDT\x01";

/// Ceiling on leaves in one exchanged state.
const MAX_STATE_LEAVES: u64 = 1_000_000;

/// Ceiling on clock entries in one leaf, i.e. on distinct replicas.
const MAX_CLOCK_ENTRIES: u32 = 4_096;

/// Why a peer's state was refused. Every variant is a rejection, never a
/// partial acceptance: a state that does not decode wholly is not merged.
#[derive(Debug, PartialEq, Eq)]
pub enum StateDecodeError {
    Truncated { need: usize, have: usize },
    BadMagic,
    TooManyLeaves(u64),
    TooManyClockEntries(u32),
    NonCanonicalClock,
    TrailingBytes(usize),
}

impl std::fmt::Display for StateDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated state: needed {need} bytes, had {have}")
            }
            Self::BadMagic => write!(f, "not an aegis CRDT state, or a different format version"),
            Self::TooManyLeaves(n) => {
                write!(f, "state declares {n} leaves; the ceiling is {MAX_STATE_LEAVES}")
            }
            Self::TooManyClockEntries(n) => write!(
                f,
                "leaf clock declares {n} entries; the ceiling is {MAX_CLOCK_ENTRIES}"
            ),
            Self::NonCanonicalClock => {
                write!(f, "clock entries are not in strictly ascending replica order")
            }
            Self::TrailingBytes(n) => write!(f, "{n} unconsumed bytes after the final leaf"),
        }
    }
}

/// A cursor that reads or refuses, and never panics or wraps.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StateDecodeError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(StateDecodeError::Truncated {
                need: n,
                have: self.bytes.len().saturating_sub(self.offset),
            })?;
        if end > self.bytes.len() {
            return Err(StateDecodeError::Truncated {
                need: n,
                have: self.bytes.len() - self.offset,
            });
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, StateDecodeError> {
        let raw = self.take(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn u64(&mut self) -> Result<u64, StateDecodeError> {
        let raw = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    fn digest(&mut self) -> Result<[u8; 32], StateDecodeError> {
        let raw = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(buf)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

impl CausalMmr {
    /// Serialise this replica's leaf set for transmission to a peer.
    ///
    /// The *leaves* are the state: clock, peaks and root are all derivable
    /// from them, so sending them too would be redundant and would let a
    /// hostile peer assert a root its own leaves do not produce. The receiver
    /// recomputes instead of trusting.
    ///
    /// The sender's own replica id is deliberately **not** on the wire. It
    /// would make the encoding non-canonical — `a ⊔ b` and `b ⊔ a` are the
    /// same state but would differ in that byte — and it would put an
    /// unauthenticated claim of identity beside the authenticated one the
    /// transport already establishes from the peer certificate. Two answers
    /// to "who sent this", one of them forgeable, is a trap rather than a
    /// convenience.
    pub fn encode_state(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 + self.leaves.len() * 48);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&(self.leaves.len() as u64).to_be_bytes());
        for leaf in &self.leaves {
            out.extend_from_slice(&leaf.replica_id.to_be_bytes());
            out.extend_from_slice(&(leaf.clock.clock.len() as u32).to_be_bytes());
            // BTreeMap iterates in ascending key order, which is exactly the
            // canonical order the decoder enforces.
            for (&replica, &seq) in &leaf.clock.clock {
                out.extend_from_slice(&replica.to_be_bytes());
                out.extend_from_slice(&seq.to_be_bytes());
            }
            out.extend_from_slice(&leaf.payload_hash);
        }
        out
    }

    /// Rebuild a replica from `encode_state` output, under `local_id`.
    ///
    /// The clock is recomputed from the leaves rather than read off the wire:
    /// a transmitted clock is an assertion, and a peer claiming a clock ahead
    /// of the leaves it actually sent would advance every replica that merged
    /// it. Recomputing makes the leaves the only thing a peer can influence.
    pub fn decode_state(bytes: &[u8], local_id: u32) -> Result<Self, StateDecodeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(STATE_MAGIC.len())? != STATE_MAGIC {
            return Err(StateDecodeError::BadMagic);
        }
        let count = reader.u64()?;
        if count > MAX_STATE_LEAVES {
            return Err(StateDecodeError::TooManyLeaves(count));
        }
        // Each leaf costs at least 4 + 4 + 32 bytes, so a count larger than the
        // remaining bytes could support is a lie; refuse before allocating.
        let minimum = (count as usize).saturating_mul(40);
        if minimum > reader.remaining() {
            return Err(StateDecodeError::Truncated {
                need: minimum,
                have: reader.remaining(),
            });
        }

        let mut leaves = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let replica_id = reader.u32()?;
            let entries = reader.u32()?;
            if entries > MAX_CLOCK_ENTRIES {
                return Err(StateDecodeError::TooManyClockEntries(entries));
            }
            let mut clock = BTreeMap::new();
            let mut previous: Option<u32> = None;
            for _ in 0..entries {
                let replica = reader.u32()?;
                let seq = reader.u64()?;
                if previous.is_some_and(|p| replica <= p) {
                    return Err(StateDecodeError::NonCanonicalClock);
                }
                previous = Some(replica);
                clock.insert(replica, seq);
            }
            let payload_hash = reader.digest()?;
            leaves.push(CausalLeaf {
                clock: VectorClock { clock },
                replica_id,
                payload_hash,
            });
        }
        if reader.remaining() != 0 {
            return Err(StateDecodeError::TrailingBytes(reader.remaining()));
        }

        // Rebuild through the same path `join` uses, so a decoded replica is
        // indistinguishable from one that was built by appending.
        let mut clock = VectorClock::new();
        for leaf in &leaves {
            clock.merge(&leaf.clock);
        }
        let mut rebuilt = CausalMmr {
            replica_id: local_id,
            clock,
            leaves: Vec::with_capacity(leaves.len()),
            peaks: Vec::new(),
        };
        leaves.sort_by_key(|leaf| leaf.sort_key());
        for leaf in leaves {
            let digest = leaf.digest();
            rebuilt.leaves.push(leaf);
            Self::carry(&mut rebuilt.peaks, rebuilt.leaves.len(), digest);
        }
        Ok(rebuilt)
    }
}

// ── PyO3 surface ────────────────────────────────────────────────────────

/// Python handle onto a `CausalMmr`.
///
/// Exposed so the reconciliation behaviour can be exercised and compared from
/// Python. It is deliberately *not* wired into `CryptographicAuditLedger`:
/// the ledger writes `aegis-mmr-inclusion-v1` roots, and this accumulator is
/// a separate structure with its own domain-separated construction.
#[pyclass(name = "CausalMmr")]
pub struct PyCausalMmr {
    inner: CausalMmr,
}

#[pymethods]
impl PyCausalMmr {
    #[new]
    fn new(replica_id: u32) -> Self {
        Self {
            inner: CausalMmr::new(replica_id),
        }
    }

    /// Append a payload; returns the new root as lowercase hex.
    fn append(&mut self, payload: &[u8]) -> String {
        hex::encode(self.inner.append(payload))
    }

    /// Current bagged root as lowercase hex.
    #[getter]
    fn root(&self) -> String {
        hex::encode(self.inner.root())
    }

    /// Merge another replica, returning the joined accumulator.
    fn join(&self, other: &PyCausalMmr) -> PyCausalMmr {
        PyCausalMmr {
            inner: self.inner.join(&other.inner),
        }
    }

    #[getter]
    fn replica_id(&self) -> u32 {
        self.inner.replica_id()
    }

    #[getter]
    fn leaf_count(&self) -> usize {
        self.inner.leaf_count()
    }

    /// This replica's vector clock as `{replica_id: sequence}`.
    #[getter]
    fn clock(&self) -> BTreeMap<u32, u64> {
        self.inner
            .clock()
            .entries()
            .map(|(&r, &s)| (r, s))
            .collect()
    }

    /// Current peaks, tallest first, as lowercase hex.
    #[getter]
    fn peaks(&self) -> Vec<String> {
        self.inner.peaks().iter().map(hex::encode).collect()
    }

    /// This replica's leaf set, in the canonical wire form.
    fn encode_state<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode_state())
    }

    /// Merge a peer's encoded state, returning the joined accumulator.
    ///
    /// Fails closed: a state that does not decode in full is not merged at
    /// all, so a truncated or malformed exchange leaves this replica exactly
    /// where it was rather than half-advanced.
    fn merge_encoded(&self, state: &[u8]) -> PyResult<PyCausalMmr> {
        let peer = CausalMmr::decode_state(state, self.inner.replica_id()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("peer state rejected: {e}"))
        })?;
        Ok(PyCausalMmr {
            inner: self.inner.join(&peer),
        })
    }

    /// Decode a peer's state on its own, without merging.
    #[staticmethod]
    fn decode_state(state: &[u8], local_id: u32) -> PyResult<PyCausalMmr> {
        let inner = CausalMmr::decode_state(state, local_id).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("peer state rejected: {e}"))
        })?;
        Ok(PyCausalMmr { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(id: u32, payloads: &[&str]) -> CausalMmr {
        let mut mmr = CausalMmr::new(id);
        for p in payloads {
            mmr.append(p.as_bytes());
        }
        mmr
    }

    /// A deterministic xorshift so the randomised laws below reproduce
    /// exactly on any machine, without pulling in a rand dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn arbitrary_replicas(seed: u64, count: usize) -> Vec<CausalMmr> {
        let mut rng = Rng(seed | 1);
        let mut out = Vec::new();
        for id in 0..count {
            let mut mmr = CausalMmr::new(id as u32);
            let appends = rng.below(6) + 1;
            for k in 0..appends {
                mmr.append(format!("r{id}-p{k}").as_bytes());
            }
            out.push(mmr);
        }
        // Exchange some state so clocks genuinely overlap rather than being
        // trivially disjoint, which would make the laws easier than reality.
        let n = out.len();
        for i in 0..n {
            let j = (rng.below(n as u64)) as usize;
            if i != j {
                let joined = out[i].join(&out[j]);
                out[i] = joined;
            }
        }
        out
    }

    // ── The semilattice laws ────────────────────────────────────────────

    #[test]
    fn join_is_idempotent() {
        for seed in 1..40u64 {
            let rs = arbitrary_replicas(seed, 3);
            for r in &rs {
                assert_eq!(r.join(r).root(), r.root(), "seed {seed}");
                assert_eq!(r.join(r).leaf_count(), r.leaf_count(), "seed {seed}");
            }
        }
    }

    #[test]
    fn join_is_commutative() {
        for seed in 1..40u64 {
            let rs = arbitrary_replicas(seed, 3);
            let (a, b) = (&rs[0], &rs[1]);
            assert_eq!(a.join(b).root(), b.join(a).root(), "seed {seed}");
        }
    }

    #[test]
    fn join_is_associative() {
        for seed in 1..40u64 {
            let rs = arbitrary_replicas(seed, 3);
            let (a, b, c) = (&rs[0], &rs[1], &rs[2]);
            let left = a.join(b).join(c);
            let right = a.join(&b.join(c));
            assert_eq!(left.root(), right.root(), "seed {seed}");
            assert_eq!(left.leaf_count(), right.leaf_count(), "seed {seed}");
        }
    }

    /// The property the laws exist to deliver: every replica converges on one
    /// root no matter what order it merges its peers in.
    #[test]
    fn all_replicas_converge_regardless_of_merge_order() {
        for seed in 1..30u64 {
            let rs = arbitrary_replicas(seed, 4);
            let forward = rs
                .iter()
                .skip(1)
                .fold(rs[0].clone(), |acc, r| acc.join(r));
            let backward = rs
                .iter()
                .rev()
                .skip(1)
                .fold(rs[rs.len() - 1].clone(), |acc, r| acc.join(r));
            assert_eq!(forward.root(), backward.root(), "seed {seed}");
        }
    }

    /// Pins the bug this implementation exists to avoid: ordering must not
    /// depend on the permutation leaves arrive in.
    #[test]
    fn merge_order_does_not_change_the_root() {
        let a = replica(1, &["alpha", "beta"]);
        let b = replica(2, &["gamma"]);
        let c = replica(3, &["delta", "epsilon"]);
        let orders = [
            a.join(&b).join(&c).root(),
            a.join(&c).join(&b).root(),
            b.join(&a).join(&c).root(),
            b.join(&c).join(&a).root(),
            c.join(&a).join(&b).root(),
            c.join(&b).join(&a).root(),
        ];
        assert!(
            orders.windows(2).all(|w| w[0] == w[1]),
            "join order changed the root: {orders:?}"
        );
    }

    // ── Causality ───────────────────────────────────────────────────────

    #[test]
    fn causal_order_is_never_inverted_by_the_sort_key() {
        // Same replica: strictly increasing clocks, so strictly increasing keys.
        let mut m = CausalMmr::new(7);
        m.append(b"first");
        m.append(b"second");
        m.append(b"third");
        let keys: Vec<_> = m.leaves.iter().map(|l| l.sort_key()).collect();
        assert!(keys[0] < keys[1] && keys[1] < keys[2]);
    }

    #[test]
    fn a_causally_earlier_clock_has_a_smaller_scalar() {
        let mut early = VectorClock::new();
        early.tick(1);
        let mut later = early.clone();
        later.tick(2);
        assert_eq!(early.partial_cmp(&later), Some(Ordering::Less));
        assert!(early.scalar() < later.scalar());
    }

    #[test]
    fn concurrent_clocks_are_detected_not_ordered() {
        let mut a = VectorClock::new();
        a.tick(1);
        let mut b = VectorClock::new();
        b.tick(2);
        assert_eq!(a.partial_cmp(&b), None);
        assert!(b.partial_cmp(&a).is_none());
    }

    #[test]
    fn merge_is_the_pointwise_maximum() {
        let mut a = VectorClock::new();
        a.tick(1);
        a.tick(1);
        let mut b = VectorClock::new();
        b.tick(1);
        b.tick(2);
        a.merge(&b);
        assert_eq!(a.get(1), 2);
        assert_eq!(a.get(2), 1);
    }

    // ── Digest and structure ────────────────────────────────────────────

    #[test]
    fn leaf_and_node_digests_are_domain_separated() {
        // The v1 weakness: an untagged leaf whose payload is two concatenated
        // child digests collides with the node over them. With tags it cannot.
        let left = [0xAAu8; 32];
        let right = [0xBBu8; 32];
        let mut node = Sha256::new();
        node.update([DOMAIN_NODE]);
        node.update(left);
        node.update(right);
        let node: [u8; 32] = node.finalize().into();

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&left);
        concatenated.extend_from_slice(&right);
        let leaf = CausalLeaf {
            clock: VectorClock::new(),
            replica_id: 0,
            payload_hash: Sha256::digest(&concatenated).into(),
        };
        assert_ne!(leaf.digest(), node);
    }

    #[test]
    fn distinct_clocks_give_distinct_digests() {
        let base = CausalLeaf {
            clock: VectorClock::new(),
            replica_id: 1,
            payload_hash: [0u8; 32],
        };
        let mut c1 = VectorClock::new();
        c1.tick(1);
        c1.tick(1);
        let mut c2 = VectorClock::new();
        c2.tick(1);
        c2.tick(2);
        let a = CausalLeaf {
            clock: c1,
            ..base.clone()
        };
        let b = CausalLeaf { clock: c2, ..base };
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn peak_count_is_the_population_count_of_the_leaf_count() {
        let mut m = CausalMmr::new(1);
        for i in 1..=32u32 {
            m.append(&i.to_be_bytes());
            assert_eq!(
                m.peaks().len(),
                (m.leaf_count() as u64).count_ones() as usize,
                "leaf_count {}",
                m.leaf_count()
            );
        }
    }

    #[test]
    fn an_empty_accumulator_has_a_defined_root() {
        let m = CausalMmr::new(1);
        assert_eq!(m.leaf_count(), 0);
        assert_ne!(m.root(), [0u8; 32]);
    }

    #[test]
    fn joining_disjoint_replicas_keeps_every_leaf() {
        let a = replica(1, &["a1", "a2", "a3"]);
        let b = replica(2, &["b1", "b2"]);
        assert_eq!(a.join(&b).leaf_count(), 5);
    }

    #[test]
    fn rejoining_an_already_merged_peer_adds_nothing() {
        let a = replica(1, &["a1", "a2"]);
        let b = replica(2, &["b1"]);
        let merged = a.join(&b);
        assert_eq!(merged.join(&b).root(), merged.root());
        assert_eq!(merged.join(&b).leaf_count(), merged.leaf_count());
    }

    #[test]
    fn tick_saturates_rather_than_wrapping() {
        let mut c = VectorClock::new();
        c.clock.insert(9, u64::MAX);
        c.tick(9);
        assert_eq!(c.get(9), u64::MAX);
    }

    #[test]
    fn scalar_saturates_rather_than_wrapping() {
        let mut c = VectorClock::new();
        c.clock.insert(1, u64::MAX);
        c.clock.insert(2, u64::MAX);
        assert_eq!(c.scalar(), u64::MAX);
    }

    // ── Wire codec ──────────────────────────────────────────────────────
    //
    // The decoder is the attack surface: it is the only part of this module a
    // peer chooses the input to. These pin what it refuses.

    #[test]
    fn a_decoded_replica_is_indistinguishable_from_an_appended_one() {
        let a = replica(1, &["a1", "a2", "a3"]);
        let round_tripped = CausalMmr::decode_state(&a.encode_state(), 1).expect("decodes");
        assert_eq!(round_tripped.root(), a.root());
        assert_eq!(round_tripped.leaf_count(), a.leaf_count());
        assert_eq!(round_tripped.peaks(), a.peaks());
    }

    #[test]
    fn merging_over_the_wire_agrees_with_merging_in_process() {
        // The property the transport exists to preserve: exchanging encoded
        // state must reach the same root as an in-process join, or gossip
        // converges on something the algebra never sanctioned.
        let a = replica(1, &["a1", "a2"]);
        let b = replica(2, &["b1", "b2", "b3"]);

        let in_process = a.join(&b);
        let over_wire = a.join(&CausalMmr::decode_state(&b.encode_state(), 1).expect("decodes"));

        assert_eq!(over_wire.root(), in_process.root());
        assert_eq!(over_wire.leaf_count(), in_process.leaf_count());
    }

    #[test]
    fn the_encoding_is_canonical() {
        // One state, one byte string — otherwise a digest over the encoding
        // disagrees with itself across replicas.
        let a = replica(1, &["a1", "a2"]);
        let b = replica(2, &["b1"]);
        // Same leaf set reached from opposite directions on different
        // replicas: the bytes must be identical, sender id included in
        // nothing.
        assert_eq!(a.join(&b).encode_state(), b.join(&a).encode_state());
        assert_eq!(a.join(&b).root(), b.join(&a).root());
    }

    #[test]
    fn a_declared_leaf_count_larger_than_the_bytes_is_refused_before_allocating() {
        // Eight bytes from the network must not be able to ask for a
        // 68-exabyte Vec.
        let mut state = replica(1, &["a1"]).encode_state();
        state[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            CausalMmr::decode_state(&state, 1).unwrap_err(),
            StateDecodeError::TooManyLeaves(u64::MAX)
        );

        // And just under the ceiling, where the count is plausible but the
        // bytes are still not there.
        state[8..16].copy_from_slice(&(MAX_STATE_LEAVES - 1).to_be_bytes());
        assert!(matches!(
            CausalMmr::decode_state(&state, 1),
            Err(StateDecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn out_of_order_clock_entries_are_refused() {
        // Hand-build a leaf whose clock entries descend. The encoder cannot
        // produce this, which is the point: only a peer can.
        let mut state = Vec::new();
        state.extend_from_slice(STATE_MAGIC);
        state.extend_from_slice(&1u64.to_be_bytes()); // one leaf
        state.extend_from_slice(&1u32.to_be_bytes()); // leaf replica
        state.extend_from_slice(&2u32.to_be_bytes()); // two clock entries
        state.extend_from_slice(&7u32.to_be_bytes());
        state.extend_from_slice(&1u64.to_be_bytes());
        state.extend_from_slice(&3u32.to_be_bytes()); // 3 < 7: descending
        state.extend_from_slice(&1u64.to_be_bytes());
        state.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            CausalMmr::decode_state(&state, 1).unwrap_err(),
            StateDecodeError::NonCanonicalClock
        );
    }

    #[test]
    fn a_repeated_clock_replica_is_refused() {
        // Equal is also non-ascending; without this a peer could send the same
        // replica twice and have the later value silently win the insert.
        let mut state = Vec::new();
        state.extend_from_slice(STATE_MAGIC);
        state.extend_from_slice(&1u64.to_be_bytes()); // one leaf
        state.extend_from_slice(&1u32.to_be_bytes()); // leaf replica
        state.extend_from_slice(&2u32.to_be_bytes()); // two clock entries
        state.extend_from_slice(&5u32.to_be_bytes());
        state.extend_from_slice(&1u64.to_be_bytes());
        state.extend_from_slice(&5u32.to_be_bytes()); // same replica again
        state.extend_from_slice(&9u64.to_be_bytes());
        state.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            CausalMmr::decode_state(&state, 1).unwrap_err(),
            StateDecodeError::NonCanonicalClock
        );
    }

    #[test]
    fn a_foreign_or_newer_format_is_refused_rather_than_misread() {
        let mut state = replica(1, &["a1"]).encode_state();
        state[7] = 0x02; // bump the format version byte
        assert_eq!(
            CausalMmr::decode_state(&state, 1).unwrap_err(),
            StateDecodeError::BadMagic
        );
        assert_eq!(
            CausalMmr::decode_state(b"", 1).unwrap_err(),
            StateDecodeError::Truncated { need: 8, have: 0 }
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // Appended bytes would otherwise ride along unnoticed, and a state
        // that decodes "mostly" is a state whose digest nobody agrees on.
        let mut state = replica(1, &["a1"]).encode_state();
        state.push(0x00);
        assert_eq!(
            CausalMmr::decode_state(&state, 1).unwrap_err(),
            StateDecodeError::TrailingBytes(1)
        );
    }

    #[test]
    fn every_truncation_is_refused_and_none_panics() {
        // The decoder sits behind a PyO3 boundary, where an unwind aborts the
        // interpreter. Every prefix must return Err, not panic.
        let state = replica(1, &["a1", "a2", "a3"]).encode_state();
        for cut in 0..state.len() {
            assert!(
                CausalMmr::decode_state(&state[..cut], 1).is_err(),
                "prefix of {cut} bytes decoded when it should have been refused"
            );
        }
        assert!(CausalMmr::decode_state(&state, 1).is_ok());
    }

    #[test]
    fn a_peer_cannot_assert_a_clock_its_leaves_do_not_support() {
        // The clock is recomputed from the leaves, so the only thing a peer
        // influences is which leaves it sends.
        let a = replica(1, &["a1", "a2"]);
        let decoded = CausalMmr::decode_state(&a.encode_state(), 9).expect("decodes");
        assert_eq!(decoded.clock().get(1), 2);
        assert_eq!(decoded.clock().get(9), 0);
    }
}
