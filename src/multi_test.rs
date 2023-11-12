use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use blake2::{Blake2b, Blake2s, Digest};
// use hex_literal::hex;

// circuit: prover claims that she knows two factors a and b of some public value c
#[derive(Copy, Clone)]
struct MultiCircuit<F:Field>{
    a: Option<F>,
    b: Option<F>,
}
// z = a* b

impl<F:Field> ConstraintSynthesizer<F> for MultiCircuit<F>{
    fn generate_constraints(self,cs: ConstraintSystemRef<F>,) 
    -> Result<(), SynthesisError> {
    let a = cs.new_witness_variable(|| Ok((self.a).unwrap()))?;
    //写法与a应该是等价的
    let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
    let c = cs.new_input_variable(|| {
        let mut a = self.a.unwrap();
        let b = self.b.unwrap();
        a.mul_assign(&b);
        Ok(a)
    })?;
    //生成了约束 c= a*b 
    cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
    
    Ok(())
  
} 
    }

struct EquationCircuit<F:Field>{
        x: Option<F>,
        b: Option<F>,
    }

//circuit for y = x^3 + x + b;
impl<F:Field> ConstraintSynthesizer<F> for EquationCircuit<F>{
    fn generate_constraints(self,cs: ConstraintSystemRef<F>,) 
    -> Result<(), SynthesisError> {
    let x_value = self.x;
    let x = cs.new_witness_variable(||x_value.ok_or(SynthesisError::AssignmentMissing))?;
    println!("x is {:?}",x);

    //x^2 
    let x_sqr_value = x_value.map(|e|e.square());
    let x_sqr = cs.new_witness_variable(|| x_sqr_value.ok_or(SynthesisError::AssignmentMissing))?;
    println!("x_sqr is {:?}",x_sqr);

    //x^3 
    let x_cub_value =x_sqr_value.map(| mut e|{
        e.mul_assign(&x_value.unwrap());
        e
    });
    
    //x^3 + x + b
    let out_value = x_cub_value.map(|mut e|{
        e.add_assign(&x_value.unwrap());
        e.add_assign(&self.b.unwrap());
        e
    });
    let out =cs.new_input_variable(|| out_value.ok_or(SynthesisError::AssignmentMissing))?;
    println!("out is {:?}",out);
  
    cs.enforce_constraint(lc!()+out, lc!()+ConstraintSystem::<F>::one(), lc!()+out)?;
   
    let flag = cs.is_satisfied();
    println!("flag is {:?}",flag);

    Ok(())
    }

}





#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::{Fr, Bls12_377};
    use ark_groth16::Groth16;
    // use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::SNARK;
    use ark_std::{ops::*, UniformRand};

    // use ark_crypto_primitives::commitment::{CommitmentGadget,CommitmentScheme};
    // use ark_crypto_primitives::commitment::
    //     blake2s::{
    //         constraints::{CommGadget, RandomnessVar},
    //         Commitment,
    //     };
    
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::Rng;

    // ark_crypto_primitives::commitment::blake2s;


    #[test]
    fn test_groth16_circuit_multiply() {
        let rng = &mut ark_std::test_rng();

        let (pk,vk) = Groth16::<Bls12_377>::circuit_specific_setup(
            MultiCircuit::<Fr>{a:None,b:None},
            rng).unwrap();
        
        println!("vk is {:?}",vk);
        let a =Fr::from(1);
        let b = Fr::from(2);
        
        let proof = Groth16::<Bls12_377>::prove(
            &pk,
            MultiCircuit::<Fr> {
                a: Some(a),
                b: Some(b),
            },
            rng,
        )
        .unwrap();
        let c =Fr::from(2);
        // validate the proof
        assert!(Groth16::<Bls12_377>::verify(&vk, &[c], &proof).unwrap());
        // assert!(!Groth16::<Bls12_377>::verify(&vk, &[d], &proof).unwrap());
    }


    // #[cfg(feature = "parallel")]
    #[test]
    fn test_groth16_circuit_equation() {
        let rng = &mut ark_std::test_rng();

        let (pk,vk) = Groth16::<Bls12_377>::circuit_specific_setup(
            EquationCircuit::<Fr>{x:None,b:None},
            rng).unwrap();
        
        let x = Fr::from(2);
        let b =Fr::from(5);
        let y = Fr::from(15);
        
        let proof = Groth16::<Bls12_377>::prove(
            &pk, EquationCircuit::<Fr>{
                x:Some(x),
                b:Some(b),
        }, rng).unwrap();
        println!("{:?}", proof);

        // assert!(Groth16::<Bls12_377>::verify(&vk, &[y], &proof).unwrap());
        assert!(Groth16::<Bls12_377>::verify(&vk, &[y], &proof).unwrap());
        
        }
       
   

}





