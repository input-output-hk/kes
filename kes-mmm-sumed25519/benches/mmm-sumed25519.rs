#[macro_use]
extern crate criterion;
use criterion::{Criterion};
use kes_mmm_sumed25519::common::{Depth};
use kes_mmm_sumed25519::compact_kes::{Sum1CompactKes, Sum2CompactKes, Sum3CompactKes, Sum4CompactKes, Sum5CompactKes, Sum6CompactKes, Sum7CompactKes};
use kes_mmm_sumed25519::traits::{KesSk, KesCompactSig};

fn bench_keygen<KES: KesSk>(depth: Depth, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(format!("KeyGen with depth: {}", depth.0).as_str(), |b| {
        b.iter(|| {
            KES::keygen(&mut seed);
        })
    });
}

fn update_with_depth<KES: KesSk>(depth: Depth, nb_update: usize, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(format!("Update with depth: {}", depth.0).as_str(), |b| {
        let (mut sk_orig, _) = KES::keygen(&mut seed);
        b.iter(|| {
            for period in 0..(nb_update - 1) {
                sk_orig.update(period).unwrap()
            }
        })
    });
}

fn update_with_depth_skip<KES: KesSk>(depth: Depth, nb_update_to_skip: usize, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(
        format!(
            "Update with depth: {}, and nb_update_to_skip: {}",
            depth.0, nb_update_to_skip
        )
        .as_str(),
        |b| {
            let (mut sk_orig, _) = KES::keygen(&mut seed);
            for period in 0..(nb_update_to_skip - 1) {
                sk_orig.update(period).unwrap()
            }

            b.iter(|| {
                sk_orig.update(nb_update_to_skip).unwrap()
            })
        },
    );
}

fn keygen_depth1(c: &mut Criterion) {
    bench_keygen::<Sum1CompactKes>(Depth(1), c)
}
fn keygen_depth2(c: &mut Criterion) {
    bench_keygen::<Sum2CompactKes>(Depth(2), c)
}
fn keygen_depth3(c: &mut Criterion) {
    bench_keygen::<Sum3CompactKes>(Depth(3), c)
}
fn keygen_depth4(c: &mut Criterion) {
    bench_keygen::<Sum4CompactKes>(Depth(4), c)
}
fn keygen_depth6(c: &mut Criterion) {
    bench_keygen::<Sum6CompactKes>(Depth(6), c)
}
fn keygen_depth7(c: &mut Criterion) {
    bench_keygen::<Sum7CompactKes>(Depth(7), c)
}

fn sign_depth5(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    let (sk, _) = Sum5CompactKes::keygen(&mut seed);
    let msg = [0u8; 256];
    c.bench_function("Signature with depth 5", |b| {
        b.iter(|| {
            sk.sign(0, &msg);
        })
    });
}

fn verify_depth7(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    let (sk, pk) = Sum7CompactKes::keygen(&mut seed);
    let msg = [0u8; 256];
    let signature = sk.sign(0, &msg);
    c.bench_function("Siganture verification with depth 12", |b| {
        b.iter(|| {
            signature.verify(0, &pk, &msg).unwrap();
        })
    });
}

fn update2_depth2(c: &mut Criterion) {
    update_with_depth::<Sum2CompactKes>(Depth(2), 2, c)
}
fn update4_depth4(c: &mut Criterion) {
    update_with_depth::<Sum4CompactKes>(Depth(4), 4, c)
}
fn update16_depth7(c: &mut Criterion) {
    update_with_depth::<Sum7CompactKes>(Depth(7), 16, c)
}

fn update128_depth7(c: &mut Criterion) {
    update_with_depth_skip::<Sum7CompactKes>(Depth(7), (1 << 7) - 1, c)
}

criterion_group!(
    keygen_benches,
    keygen_depth1,
    keygen_depth2,
    keygen_depth3,
    keygen_depth4,
    keygen_depth6,
    keygen_depth7,
);

criterion_group!(
    keyopts_benches,
    sign_depth5,
    verify_depth7,
    update2_depth2,
    update4_depth4,
    update16_depth7,
    update128_depth7
);

criterion_main!(keygen_benches, keyopts_benches);
