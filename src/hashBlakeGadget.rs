

mod test {
use ark_crypto_primitives::prf::{PRFGadget, PRF};
use ark_crypto_primitives::prf::blake2s::{constraints::evaluate_blake2s, Blake2s as B2SPRF};
use ark_bls12_377::Fr;
use ark_relations::r1cs::ConstraintSystem;
use ark_crypto_primitives::prf::blake2s::constraints::{Blake2sGadget, OutputVar};

use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::alloc::AllocVar;
use ark_std::rand::Rng;

    #[test]
    fn test_blake2s_prf() {

        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let mut input = [0u8; 32];
        rng.fill(&mut input);
        println!("num constraints0 is {}",cs.num_constraints());
        println!("Input: {:?}", input);
       
        let seed_var = Blake2sGadget::new_seed(cs.clone(), &seed);
        println!("num constraints1 is {}",cs.num_constraints());
        let input_var =
            UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), &input).unwrap();
        println!("num constraints2 is {}",cs.num_constraints());
        let out = B2SPRF::evaluate(&seed, &input).unwrap();
        println!("outis: {:?}", out);
        println!("num constraints3 is {}",cs.num_constraints());
        let actual_out_var = <Blake2sGadget as PRFGadget<_, Fr>>::OutputVar::new_input(
            ark_relations::ns!(cs, "declare_output"),
            || Ok(out),
        )
        .unwrap();
        
        println!("num constraints4 is {}",cs.num_constraints());

        let output_var = Blake2sGadget::evaluate(&seed_var, &input_var).unwrap();

        println!("num of input : {:?}", cs.num_instance_variables());
        println!("num of witness : {:?}", cs.num_witness_variables());
        // let a = <Blake2sGadget as PRFGadget<_, Fr>>::OutputVar::new_input(
        //     ark_relations::ns!(cs, "declare_output"),
        //     || Ok(output),
        // ).unwrap();
        println!("num constraints5 is {}",cs.num_constraints());

        output_var.enforce_equal(&actual_out_var).unwrap();
        println!("num of witness : {:?}", cs.num_witness_variables());
        println!("num of input : {:?}", cs.num_instance_variables());

        println!("num constraints6 is {}",cs.num_constraints());
        println!("num of input : {:?}", cs.num_instance_variables());
        if !cs.is_satisfied().unwrap() {
            println!(
                "which is unsatisfied: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
        assert!(cs.is_satisfied().unwrap());
        println!("num constraints7 is {}",cs.num_constraints());
    }
}