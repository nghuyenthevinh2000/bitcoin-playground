use ark_groth16::{Groth16};
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Result},
};

#[derive(Copy, Clone)]
struct MultiplyDemoCircuit<F:Field> {
    a: Option<F>,
    b: Option<F>,
}

impl <ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MultiplyDemoCircuit<ConstraintF> {
    fn generate_constraints(
        self, 
        cs: ConstraintSystemRef<ConstraintF>
    ) -> Result<()> {
        // define new Field a
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        // define new Field b
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        // define 
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_snark::SNARK;
    use ark_std::rand::{SeedableRng};
    use ark_std::{ops::*, UniformRand};

    #[test]
    fn test_groth16_circuit_multiply(){
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(1234);

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr>{a: None, b: None},
            rng
        ).unwrap();

        // construct a test
        let a = BlsFr::rand(rng);
        let b = BlsFr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);

        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            MultiplyDemoCircuit::<BlsFr> {
                a: Some(a),
                b: Some(b),
            },
            rng,
        )
        .unwrap();

        // validate the proof
        assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
        assert!(!Groth16::<Bls12_381>::verify(&vk, &[a], &proof).unwrap());
    }
}