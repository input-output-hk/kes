//! This module contains the macros to build the KES algorithms.

macro_rules! sum_kes_buff {
    ($name:ident, $signame:ident, $sk:ident, $sigma:ident, $depth:expr, $doc:expr) => {
        #[derive(Zeroize)]
        #[zeroize(drop)]
        #[doc=$doc]
        pub struct $name([u8; 64 + $depth * 32 + $depth * (32 * 2)]);

        /// Structure that represents that KES signature.
        pub struct $signame {
            sigma: $sigma,
            lhs_pk: PublicKey,
            rhs_pk: PublicKey,
        }

        impl KesSk for $name {
            const SIZE: usize = 64 + $depth * 32 + $depth * (32 * 2);
            type Sig = $signame;

            fn keygen_kes(master_seed: &mut Seed) -> (Self, PublicKey) {
                let mut data = [0u8; Self::SIZE];
                let (mut r0, mut seed) = master_seed.split_seed();
                // We copy the seed before overwriting with zeros (in the `keygen_kes` call).
                data[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&seed.0);

                let (sk_0, pk_0) = $sk::keygen_kes(&mut r0);
                let (_, pk_1) = $sk::keygen_kes(&mut seed);

                let pk = hash(&pk_0, &pk_1);

                // We write the keys to the main data.
                data[..$sk::SIZE].copy_from_slice(&sk_0.0);
                data[$sk::SIZE + 32..$sk::SIZE + 64].copy_from_slice(&pk_0.as_bytes());
                data[$sk::SIZE + 64..$sk::SIZE + 96].copy_from_slice(&pk_1.as_bytes());

                // We overwrite the master seed with zeroes
                master_seed.set_zero();
                (Self(data), pk)
            }

            fn sign_kes(&self, period: usize, m: &[u8]) -> Self::Sig {
                let t0 = Depth($depth).half();
                let sigma = if period < t0 {
                    $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])
                        .expect("Invalid key bytes")
                        .sign_kes(period, m)
                } else {
                    $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])
                        .expect("Invalid key bytes")
                        .sign_kes(period - t0, m)
                };

                let lhs_pk =
                    PublicKey::from_bytes(&self.as_bytes()[$sk::SIZE + 32..$sk::SIZE + 64])
                        .expect("Won't fail as slice has size 32");
                let rhs_pk =
                    PublicKey::from_bytes(&self.as_bytes()[$sk::SIZE + 64..$sk::SIZE + 96])
                        .expect("Won't fail as slice has size 32");
                $signame {
                    sigma,
                    lhs_pk,
                    rhs_pk,
                }
            }

            fn update_kes(&mut self, period: usize) -> Result<(), Error> {
                if period + 1 == Depth($depth).total() {
                    return Err(Error::KeyCannotBeUpdatedMore);
                }

                match (period + 1).cmp(&Depth($depth).half()) {
                    Ordering::Less => {
                        $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])?.update_kes(period)?
                    }
                    Ordering::Equal => {
                        let mut seed =
                            Seed::from_slice(&self.as_bytes()[$sk::SIZE..$sk::SIZE + 32]);
                        self.0[..$sk::SIZE]
                            .copy_from_slice($sk::keygen_kes(&mut seed).0.as_bytes());
                        self.0[$sk::SIZE..$sk::SIZE + 32].copy_from_slice(&[0u8; 32]);
                    }
                    Ordering::Greater => $sk::from_bytes(&self.as_bytes()[..$sk::SIZE])?
                        .update_kes(period - &Depth($depth).half())?,
                }

                Ok(())
            }

            fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != Self::SIZE {
                    return Err(Error::InvalidSecretKeySize(bytes.len()));
                }

                let mut key = [0u8; Self::SIZE];
                key.copy_from_slice(bytes);
                Ok(Self(key))
            }

            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl KesSig for $signame {
            fn verify_kes(&self, period: usize, pk: &PublicKey, m: &[u8]) -> Result<(), Error> {
                if &hash(&self.lhs_pk, &self.rhs_pk) != pk {
                    return Err(Error::InvalidHashComparison);
                }

                if period < Depth($depth).half() {
                    self.sigma.verify_kes(period, &self.lhs_pk, m)?;
                } else {
                    self.sigma
                        .verify_kes(period - &Depth($depth).half(), &self.rhs_pk, m)?
                }

                Ok(())
            }
        }
    };
}
