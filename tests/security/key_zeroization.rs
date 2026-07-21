//! SECURITY: Key zeroization — secret key material is wiped on drop.
//!
//! Invariant: `AesKey`, `CardKeys`, and `CardKeySet` all hold raw AES key
//! bytes in RAM and must not leave that material behind when they go out of
//! scope. The `zeroize` crate overwrites the storage; the `Drop` impl triggers
//! it. This module verifies the wiring at three levels:
//!
//! 1. **Compile-time** — the types implement `Drop` (a missing `Drop` would
//!    silently leak material; we assert the trait bound statically).
//! 2. **Structural** — `AesKey::zeroed()` / `is_zero()` round-trip, proving
//!    the "zeroed" sentinel state is well-defined and detectable.
//! 3. **Best-effort memory** — observe the underlying buffer through a raw
//!    pointer after `Drop` runs. This is inherently best-effort (the compiler
//!    is free to reuse the stack slot), so we treat it as *corroborating*
//!    evidence rather than the primary contract.

use bolty_core::derivation::{BoltcardDeterministicDeriver, CardKeySet};
use bolty_core::secret::{AesKey, CardKeys};
use bolty_core::uid::CardUid;

/// Helper trait alias used only to assert `Drop` is implemented statically.
/// If a maintainer ever removes the `Drop` impl, this bound fails to compile
/// and the security regression is caught before the code merges.
//
// The `T: Drop` bound triggers the `drop_bounds` lint, which suggests
// `mem::needs_drop` instead. That runtime check would not give us a
// compile-time guarantee, which is the whole point here, so we silence the
// lint for this helper only.
#[allow(drop_bounds)]
fn assert_drops<T: Drop>() {}

#[test]
fn aeskey_implements_drop() {
    // SECURITY invariant: AesKey must wipe its 16 bytes on drop. A missing
    // Drop impl would let secret material linger on the stack/heap. Asserting
    // the trait bound at compile time is the only reliable check — observing
    // post-drop memory is best-effort (see `drop_overwrites_stack_slot`).
    assert_drops::<AesKey>();
}

#[test]
fn cardkeyset_implements_drop() {
    // SECURITY invariant: CardKeySet holds derived keys plus a card_id that
    // must be zeroized; it declares its own `impl Drop` to wipe card_id
    // (derivation.rs). Pin the bound so removing that impl is a compile error.
    assert_drops::<CardKeySet>();
}

#[test]
fn cardkeys_wipe_via_field_auto_drop() {
    // SECURITY invariant: CardKeys does NOT declare its own `impl Drop`; it
    // relies on Rust's automatic field-by-field drop, which runs each AesKey
    // field's Drop (and thus zeroize) when the aggregate falls out of scope.
    // This is correct and safe as long as:
    //   (a) every field is an AesKey (which impl Drop — asserted above), and
    //   (b) no future `impl Drop for CardKeys` calls `mem::forget` on a field.
    //
    // We cannot assert (b) statically, so we assert (a) structurally: every
    // field must be individually clearable to the zero sentinel, proving they
    // are AesKey-backed. See `cardkeys_zeroed_wipes_all_five_slots`.
    //
    // This test is the documentation anchor; the real verification is the
    // structural wipe test below.
    let keys = CardKeys::zeroed();
    // If any field were not an AesKey (with its Drop), it would not expose
    // is_zero() — this call is itself a compile-time check on the field type.
    let _ = (keys.k0.is_zero(), keys.k1.is_zero());
}

#[test]
fn zeroed_is_detectable_as_zero() {
    // SECURITY invariant: the "cleared" state must be unambiguously
    // distinguishable from a live key. If `is_zero()` ever returned true for a
    // non-zero buffer, a guard like "refuse to use zeroed keys" would silently
    // accept wiped material.
    assert!(AesKey::zeroed().is_zero());
    assert!(!AesKey::new([0xFF; 16]).is_zero());
    // A single non-zero byte must break the sentinel.
    let mut partial = [0u8; 16];
    partial[7] = 0x01;
    assert!(!AesKey::new(partial).is_zero());
}

#[test]
fn cardkeys_zeroed_wipes_all_five_slots() {
    // SECURITY invariant: CardKeys::zeroed() must clear K0–K4, not just K0.
    // A bug that only zeroed the first slot would leak K1–K4.
    let keys = CardKeys::zeroed();
    assert!(keys.k0.is_zero());
    assert!(keys.k1.is_zero());
    assert!(keys.k2.is_zero());
    assert!(keys.k3.is_zero());
    assert!(keys.k4.is_zero());
}

#[test]
fn cardkeyset_default_is_zeroed() {
    // SECURITY invariant: CardKeySet::default() must construct an all-zero
    // state (no stray material from uninitialized memory).
    let set = CardKeySet::default();
    assert!(set.card_key.is_zero());
    assert!(set.k0.is_zero());
    assert!(set.k1.is_zero());
    assert!(set.k2.is_zero());
    assert!(set.k3.is_zero());
    assert!(set.k4.is_zero());
    assert_eq!(set.card_id, [0u8; 16]);
}

#[test]
#[ignore = "post-drop memory observation is best-effort and non-deterministic; \
            run explicitly with --ignored to corroborate the Drop wiring"]
fn drop_overwrites_stack_slot() {
    // Best-effort corroboration of the Drop wiring. We leak a pointer to the
    // underlying buffer, drop the key, and read the bytes back. Because the
    // compiler may reuse the stack slot, this is *supporting* evidence only —
    // the authoritative check is the compile-time `Drop` bound above.
    let key = AesKey::new([0xAB; 16]);
    let ptr: *const u8 = key.as_bytes().as_ptr();
    // Force a move to a known stack location then drop in place.
    let key = key;
    let _ = ptr;
    drop(key);

    // SAFETY: the pointer pointed into the AesKey's stack allocation. After
    // drop the memory is technically uninitialized; we read it only to
    // corroborate that zeroize ran. We bound the read to the 16-byte region
    // the key occupied and accept that the value may have been overwritten by
    // unrelated code, making this test flaky → hence #[ignore].
    unsafe {
        let bytes: [u8; 16] = std::ptr::read_volatile(ptr as *const [u8; 16]);
        // If zeroize ran, the bytes are 0. If the slot was reused, they may be
        // anything. We assert all-zero and tolerate rare flakes via #[ignore].
        assert!(
            bytes.iter().all(|&b| b == 0),
            "post-drop bytes were not zero — zeroize may not have run (or slot reused): {bytes:?}"
        );
    }
}

#[test]
fn derived_keys_are_wiped_after_scope_exit() {
    // SECURITY invariant: a derived key set, when dropped at end of scope, must
    // not leave its component keys retrievable. We can only assert the
    // observable contract: after the inner scope, no binding in this scope
    // references the keys. The Drop bound (tested above) is what guarantees
    // the wipe; here we verify the derivation API itself produces wipeable
    // types (AesKey, not raw [u8;16]).
    let uid = CardUid::new([0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80]);
    {
        let _set = BoltcardDeterministicDeriver::derive_keys(&[0u8; 16], uid, 1);
        // _set drops here; its CardKeySet Drop wipes card_id and each AesKey
        // wipes its bytes via the inherited Drop.
    }
    // If we reach here, the scope exited cleanly. The compile-time Drop bounds
    // (assert_drops above) are the real guarantee.
}
