// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::PrimeField;
use ark_marlin::{Marlin, SimpleHashFiatShamirRng};
use ark_mnt4_298::{Fr as MNT4Fr, MNT4_298};
use ark_mnt4_753::{Fr as MNT4BigFr, MNT4_753};
use ark_mnt6_298::{Fr as MNT6Fr, MNT6_298};
use ark_mnt6_753::{Fr as MNT6BigFr, MNT6_753};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{ops::Mul, UniformRand};
use blake2::Blake2s;
use rand_chacha::ChaChaRng;
// GRT modify
use std::env;
use std::ops::Div;
// GRT modify
const NUM_PROVE_REPEATITIONS: usize = 5;
const NUM_VERIFY_REPEATITIONS: usize = 10;

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

macro_rules! marlin_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = Marlin::<
            $bench_field,
            SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::universal_setup(65536, 65536, 3 * 65536, rng)
        .unwrap();
        let (pk, _) = Marlin::<
            $bench_field,
            SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::index(&srs, c)
        .unwrap();

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_PROVE_REPEATITIONS {
            let _ = Marlin::<
                $bench_field,
                SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
            >::prove(&pk, c.clone(), rng)
            .unwrap();
        }

        println!(
            "per-constraint proving time for {}: {} ns/constraint",
            stringify!($bench_pairing_engine),
            start.elapsed().as_nanos() / NUM_PROVE_REPEATITIONS as u128 / 65536u128
        );
    };
}

macro_rules! marlin_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let srs = Marlin::<
            $bench_field,
            SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::universal_setup(65536, 65536, 3 * 65536, rng)
        .unwrap();
        let (pk, vk) = Marlin::<
            $bench_field,
            SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::index(&srs, c)
        .unwrap();
        let proof = Marlin::<
            $bench_field,
            SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
        >::prove(&pk, c.clone(), rng)
        .unwrap();

        let v = c.a.unwrap().mul(c.b.unwrap());

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_VERIFY_REPEATITIONS {
            let _ = Marlin::<
                $bench_field,
                SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
            >::verify(&vk, &vec![v], &proof, rng)
            .unwrap();
        }

        println!(
            "verifying time for {}: {} ns",
            stringify!($bench_pairing_engine),
            start.elapsed().as_nanos() / NUM_VERIFY_REPEATITIONS as u128
        );
    };
}

fn bench_prove() {
    marlin_prove_bench!(bls, BlsFr, Bls12_381);
    marlin_prove_bench!(mnt4, MNT4Fr, MNT4_298);
    marlin_prove_bench!(mnt6, MNT6Fr, MNT6_298);
    marlin_prove_bench!(mnt4big, MNT4BigFr, MNT4_753);
    marlin_prove_bench!(mnt6big, MNT6BigFr, MNT6_753);
}

fn bench_verify() {
    marlin_verify_bench!(bls, BlsFr, Bls12_381);
    marlin_verify_bench!(mnt4, MNT4Fr, MNT4_298);
    marlin_verify_bench!(mnt6, MNT6Fr, MNT6_298);
    marlin_verify_bench!(mnt4big, MNT4BigFr, MNT4_753);
    marlin_verify_bench!(mnt6big, MNT6BigFr, MNT6_753);
}

// GRT modify
macro_rules! marlin_prove_bench_test {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {

        const MINIMUM_DEGREE: usize = 10;
        const MAXIMUM_DEGREE: usize = 23;
        for num_constraints in MINIMUM_DEGREE..MAXIMUM_DEGREE {
            let rng = &mut ark_std::test_rng();
            let c = DummyCircuit::<$bench_field> {
                a: Some(<$bench_field>::rand(rng)),
                b: Some(<$bench_field>::rand(rng)),
                num_variables:  (1 << (num_constraints)) - 100,
                num_constraints: (1 << num_constraints) - 100,
            };

            let srs = Marlin::<
                $bench_field,
                SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
            >::universal_setup((1 << num_constraints), (1 << num_constraints), 3 * (1 << num_constraints), rng)
            .unwrap();
            let (pk, _) = Marlin::<
                $bench_field,
                SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
            >::index(&srs, c)
            .unwrap();

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_PROVE_REPEATITIONS {
                println!("@@ GRT prove one degree: {:?}; start", num_constraints);
                let start1 = ark_std::time::Instant::now();
                let _ = Marlin::<
                    $bench_field,
                    SonicKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                    SimpleHashFiatShamirRng<Blake2s, ChaChaRng>,
                >::prove(&pk, c.clone(), rng)
                .unwrap();
                println!("@@ GRT prove one degree: {:?}; time: {:?}", num_constraints, start1.elapsed());
            }

        println!("###### GRT average prove degree:{:?}; time for {}: {:?}", num_constraints, stringify!($bench_pairing_engine), start.elapsed().div(NUM_PROVE_REPEATITIONS as u32));
        }

    };
}

// GRT modify
fn bench_prove_test() {
    marlin_prove_bench_test!(bls, BlsFr, Bls12_381);
}

fn main() {
    // GRT modify
    // bench_prove();
    // bench_verify();
    bench_prove_test();
}
