// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! The two published `block-buffer` panic-corruption proofs, run against the
//! version this crate actually links.
//!
//! `block-buffer 0.10.4` carried an advisory (CVSS 6.3, no CVE identifier
//! assigned — which is why an OSV query for it returns nothing): a caught
//! panic could leave the cursor of `EagerBuffer` or `ReadBuffer` in a state
//! violating that type's cursor invariant, and the next `get_pos()` then
//! reached the `unreachable_unchecked` that assumes the invariant holds. That
//! is undefined behaviour, and it sat under every SHA-256 and HMAC call on the
//! evidence path via `digest 0.10`.
//!
//! The two types do not share an invariant, and conflating them produces a
//! test that fails against correct behaviour: `EagerBuffer`'s cursor counts
//! buffered bytes and must satisfy `pos < block_size`, while `ReadBuffer`'s
//! counts bytes already read and must satisfy `1 <= pos <= block_size`, where
//! `pos == block_size` simply means fully consumed.
//!
//! Both proofs are reproduced here rather than paraphrased. They are the
//! advisory's own tests, ported to the 0.12 API, and they matter because a
//! version bump on its own proves only that the number changed:
//!
//! - `EagerBuffer` keeps its cursor in the last byte of the internal block.
//!   `digest_blocks` overwrites that byte with input before calling the
//!   caller's `compress`, so a panic inside `compress` used to leave the
//!   cursor holding attacker-influenced input.
//! - `ReadBuffer` keeps its cursor in `buffer[0]`, and `write_block` hands
//!   `gen_block` the whole block before restoring it, so a panic after
//!   `block[0]` was written used to leave an invalid cursor.
//!
//! 0.12.1 wraps both windows in a `ResetGuard` whose `Drop` restores the
//! invariant during unwind. These tests exercise that guard.
//!
//! **Run them under Miri to make the assertion meaningful:**
//!
//! ```text
//! cargo +nightly miri test --test block_buffer_panic_safety
//! ```
//!
//! Without Miri they only confirm the calls return a value in range; the
//! `unreachable_unchecked` is UB that a normal build is free not to trap.
//! Under Miri, reaching it is a hard error, so a pass is a real result — for
//! the two shapes tested, on this version. It is not a proof that the crate
//! is free of unsoundness.

use block_buffer::array::sizes::U4;
use block_buffer::{EagerBuffer, ReadBuffer};

/// Advisory PoC 1: a panic inside `compress` must not corrupt the cursor.
///
/// `EagerBuffer::<U4>::new(&[1, 2])` starts with `pos == 2`. Feeding two more
/// bytes completes the block, so `digest_blocks` writes `0xff` into the byte
/// holding the cursor and then calls `compress`, which panics. Catching that
/// panic and calling `get_pos()` is what used to hit `unreachable_unchecked`.
#[test]
fn a_panic_in_compress_leaves_the_eager_cursor_valid() {
    let mut buffer = EagerBuffer::<U4>::new(&[1, 2]);

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        buffer.digest_blocks(&[3, 0xff], |_| panic!("simulated compression failure"));
    }));
    assert!(unwound.is_err(), "the panic must actually have been caught");

    // The call the advisory identifies as the UB site.
    let pos = buffer.get_pos();
    assert!(
        pos < 4,
        "cursor {pos} violates the pos < block_size invariant after a caught panic"
    );

    // And the buffer must still be usable rather than merely non-crashing.
    buffer.digest_blocks(&[7, 8, 9, 10], |_| {});
    assert!(buffer.get_pos() < 4);
}

/// Advisory PoC 2: a panic inside `gen_block` must not corrupt the cursor.
///
/// `ReadBuffer` stores its cursor in `buffer[0]`. `write_block` gives
/// `gen_block` mutable access to the whole block before restoring that byte,
/// so writing `0xff` and panicking used to leave an invalid cursor behind.
#[test]
fn a_panic_in_gen_block_leaves_the_read_cursor_valid() {
    let mut buffer = ReadBuffer::<U4>::default();

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        buffer.write_block(
            1,
            |block| {
                block[0] = 0xff;
                panic!("simulated block generation failure");
            },
            |_| {},
        );
    }));
    assert!(unwound.is_err(), "the panic must actually have been caught");

    // `ReadBuffer` carries a different invariant from `EagerBuffer`: its
    // cursor counts bytes already read, so `read.rs` requires
    // `pos != 0 && pos <= block_size` and `pos == block_size` means "fully
    // consumed". Asserting `pos < block_size` here would fail against correct
    // behaviour.
    let pos = buffer.get_pos();
    assert!(
        (1..=4).contains(&pos),
        "cursor {pos} violates the 1 <= pos <= block_size invariant after a caught panic"
    );

    // And the buffer must still be usable rather than merely non-crashing.
    let mut out = [0u8; 2];
    buffer.read(&mut out, |block| block.fill(0xab));
    assert!((1..=4).contains(&buffer.get_pos()));
}

/// A panic during `read_fn`, after `gen_block` succeeded, is the other half of
/// the same window and is not covered by either published proof.
#[test]
fn a_panic_in_read_fn_leaves_the_read_cursor_valid() {
    let mut buffer = ReadBuffer::<U4>::default();

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        buffer.write_block(
            1,
            |block| block[0] = 0xff,
            |_| panic!("simulated read failure"),
        );
    }));
    assert!(unwound.is_err(), "the panic must actually have been caught");

    let pos = buffer.get_pos();
    assert!(
        (1..=4).contains(&pos),
        "cursor {pos} violates the 1 <= pos <= block_size invariant after a caught panic"
    );
}
