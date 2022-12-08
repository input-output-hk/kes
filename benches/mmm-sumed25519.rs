#[macro_use]
extern crate criterion;
use criterion::Criterion;
use kes_summed_ed25519::kes::{
    Sum1CompactKes, Sum2CompactKes, Sum3CompactKes, Sum4CompactKes, Sum5CompactKes, Sum6CompactKes,
    Sum7CompactKes,
};
use kes_summed_ed25519::traits::{KesCompactSig, KesSk};

fn bench_keygen<KES: KesSk>(depth: usize, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(format!("KeyGen with depth: {}", depth).as_str(), |b| {
        b.iter(|| {
            KES::keygen(&mut seed);
        })
    });
}

fn update_with_depth<KES: KesSk>(depth: usize, nb_update: usize, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(format!("Update with depth: {}", depth).as_str(), |b| {
        let (mut sk_orig, _) = KES::keygen(&mut seed);
        b.iter(|| {
            for _ in 0..(nb_update - 1) {
                sk_orig.update().unwrap()
            }
        })
    });
}

fn update_with_depth_skip<KES: KesSk>(depth: usize, nb_update_to_skip: usize, c: &mut Criterion) {
    let mut seed = [0u8; 32];
    c.bench_function(
        format!(
            "Update with depth: {}, and nb_update_to_skip: {}",
            depth, nb_update_to_skip
        )
        .as_str(),
        |b| {
            let (mut sk_orig, _) = KES::keygen(&mut seed);
            for _ in 0..(nb_update_to_skip - 1) {
                sk_orig.update().unwrap()
            }

            b.iter(|| sk_orig.update().unwrap())
        },
    );
}

fn keygen_depth1(c: &mut Criterion) {
    bench_keygen::<Sum1CompactKes>(1, c)
}
fn keygen_depth2(c: &mut Criterion) {
    bench_keygen::<Sum2CompactKes>(2, c)
}
fn keygen_depth3(c: &mut Criterion) {
    bench_keygen::<Sum3CompactKes>(3, c)
}
fn keygen_depth4(c: &mut Criterion) {
    bench_keygen::<Sum4CompactKes>(4, c)
}
fn keygen_depth6(c: &mut Criterion) {
    bench_keygen::<Sum6CompactKes>(6, c)
}
fn keygen_depth7(c: &mut Criterion) {
    bench_keygen::<Sum7CompactKes>(7, c)
}

fn sign_depth5(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    let (sk, _) = Sum5CompactKes::keygen(&mut seed);
    let msg = [0u8; 256];
    c.bench_function("Signature with depth 5", |b| {
        b.iter(|| {
            sk.sign(&msg);
        })
    });
}

fn verify_depth7(c: &mut Criterion) {
    let mut seed = [0u8; 32];
    let (sk, pk) = Sum7CompactKes::keygen(&mut seed);
    let msg = [0u8; 256];
    let signature = sk.sign(&msg);
    c.bench_function("Siganture verification with depth 12", |b| {
        b.iter(|| {
            signature.verify(0, &pk, &msg).unwrap();
        })
    });
}

fn update2_depth2(c: &mut Criterion) {
    update_with_depth::<Sum2CompactKes>(2, 2, c)
}
fn update4_depth4(c: &mut Criterion) {
    update_with_depth::<Sum4CompactKes>(4, 4, c)
}
fn update16_depth7(c: &mut Criterion) {
    update_with_depth::<Sum7CompactKes>(7, 16, c)
}

fn update128_depth7(c: &mut Criterion) {
    update_with_depth_skip::<Sum7CompactKes>(7, (1 << 7) - 1, c)
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
