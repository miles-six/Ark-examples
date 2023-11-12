
mod test{
    use ark_bls12_377::Bls12_377;
    use ark_ff::Field;
    use ark_r1cs_std::prelude::AllocVar;
    use ark_groth16;
    use ark_relations::lc;
    use ark_ff::Fp256;
    use ark_std::borrow::Borrow;
    use ark_std::{start_timer, end_timer};
    
    #[test]
    fn test_circuit(){
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::FieldVar;
    use ark_relations::r1cs::SynthesisError;
    use ark_bls12_377::Fr;
    use ark_std::rand::Rng;
    use ark_snark::SNARK;
    use std::ops::Add;
    use std::ops::Mul;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSynthesizer;

    //out = x^3+x+y+5;
    struct TestCircuit {
        x: u64,
        y: u64,
        out:u64,
    }
    
    impl <F:Field+ ark_ff::PrimeField+ ark_relations::r1cs::Field> ConstraintSynthesizer<F> for TestCircuit 
    where Fp256<ark_bls12_377::FrParameters>: Borrow<F>
    {
        fn generate_constraints(self,cs: ConstraintSystemRef<F>,) 
    -> Result<(), SynthesisError> {
                // let cs = ConstraintSystem::<Fr>::new_ref();
                println!("num_witness_variables {:?}", cs.num_witness_variables());
                println!("num_instance_variables {:?}", cs.num_instance_variables());
                let x_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.x))).unwrap();
                println!("num_witness_variables {:?}", cs.num_witness_variables());
                let y_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.y))).unwrap();
                println!("num_witness_variables {:?}", cs.num_witness_variables());

                // let out_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.out))).unwrap();
                let five_var = FpVar::new_constant(cs.clone(), Fr::from(5)).unwrap();

                let x_square_var = x_var.square()?;  //x^2
                println!("num_witness_variables {:?}", cs.num_witness_variables());
                let x_cubic_var  = x_square_var.mul(&x_var); //x^3
                println!("num_witness_variables {:?}", cs.num_witness_variables());
                let x_cubic_plus_x_var = x_cubic_var.add(&x_var); //x^3+x

                let x_cubic_plus_x_plus_y_var = x_cubic_plus_x_var.add(y_var); //x^3+x+y

                let x_cubic_plus_x_plus_y_plus_five_var = x_cubic_plus_x_plus_y_var.add(five_var); //x^3+x+y+5

                

                let out_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.out))).unwrap();
                let _ = out_var.enforce_equal(&x_cubic_plus_x_plus_y_plus_five_var);

                
                let is_satisfied = cs.is_satisfied();
                println!("is_satisfied {:?}", is_satisfied);
                println!("num_constraints {:?}", cs.num_constraints());
                println!("num_witness_variables {:?}", cs.num_witness_variables());
                println!("num_instance_variables {:?}", cs.num_instance_variables());
            Ok(())
        }
    }

    // let cs = ConstraintSystem::<Fr>::new_ref(); //create a new constraint system

    let circuit = TestCircuit{x:0, y:0,out:0};
    // circuit.generate_constraints(cs.clone()).unwrap();
   
    
    let rng = &mut ark_std::test_rng();
    let (pk,vk) = 
    Groth16::<Bls12_377>::circuit_specific_setup(circuit,rng).unwrap();

    // println!("pk is {:?}", pk);
    
    println!("vk is {:?}", vk);
    
    let circuit = TestCircuit{x:3, y:1,out:35};
    let out = Fr::from(35);
    let proof = Groth16::<Bls12_377>::prove(
        &pk,
        circuit,
        rng,
    )
    .unwrap();

    let result = Groth16::<Bls12_377>::verify(&vk, &[out], &proof);
    println!("result  = {:?}", result);
    assert!(Groth16::<Bls12_377>::verify(&vk, &[out], &proof).unwrap());

   
}
}




