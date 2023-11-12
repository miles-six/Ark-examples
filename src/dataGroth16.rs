use ark_ff::Field;
use ark_ff::ToConstraintField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_relations::r1cs::Namespace;
use ark_crypto_primitives::prf::{PRFGadget, PRF};
use ark_crypto_primitives::prf::blake2s::{constraints::evaluate_blake2s, Blake2s as B2SPRF};
use ark_bls12_377::{Bls12_377,Fr};
use ark_groth16::Groth16;
use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_r1cs_std::{uint8::UInt8, fields::fp::FpVar, ToConstraintFieldGadget};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::alloc::AllocVar;
use ark_std::rand::Rng;
use ark_crypto_primitives::SNARK;
use ark_ff::Fp256;
use ark_bls12_377::FrParameters;

struct DataCircuit {
    address: [u8; 32],
    k : [u8; 32],
    hash_k: [u8; 32],
}

impl <F:Field + ark_ff::PrimeField> ConstraintSynthesizer<F> for DataCircuit
where Namespace<Fp256<FrParameters>>: From<ConstraintSystemRef<F>> 

{
    fn generate_constraints(self,cs: ConstraintSystemRef<F>,) 
        -> Result<(), SynthesisError> {

            //给变量赋值
            let seed_var = Blake2sGadget::new_seed(cs.clone(), &self.k);
            let input_var =
                UInt8::new_witness_vec(cs.clone(), &self.address).unwrap();
            let actual_out_var = <Blake2sGadget as PRFGadget<_, Fr>>::OutputVar::new_input(
                    cs.clone(),
                    || Ok(self.hash_k)
                ).unwrap();

            //通过Blake2sGadget 计算随机数 k=seed的哈希 及添加约束
            let output_var = Blake2sGadget::evaluate(&seed_var, &input_var).unwrap();
            //验证Blake2约束
            output_var.enforce_equal(&actual_out_var).unwrap();
            println!("num_constraints after blake {:?}", cs.num_constraints());
            
            //实现 k + address ，并添加约束
            for i in 0..32 {
                let c = cs.new_witness_variable(||Ok(F::from(self.address[i]))).unwrap();
                let d = cs.new_witness_variable(||Ok(F::from(self.k[i]))).unwrap();
                let e_value = self.address[i] as u16 + self.k[i] as u16;
                let e =cs.new_input_variable(||Ok(F::from(e_value))).unwrap();
                cs.enforce_constraint(lc!()+c+d, lc!()+ConstraintSystem::<F>::one(), lc!()+e);
            }
            println!("num_constraints after add {:?}", cs.num_constraints());
            println!("is satisified {:?}",cs.is_satisfied());

        Ok(())
        }
    }

mod test {
    use std::{hash, result};
    use std::str::FromStr;

    use super::*;
    use ark_std::rand::Rng;
    use blake2::{Blake2b, Blake2s, Digest};
    use ark_crypto_primitives::prf::blake2s::{constraints::evaluate_blake2s, Blake2s as B2SPRF};
    use ark_crypto_primitives::PRF;
    #[test]
    fn test_blake2_withoutconstraints() {
        let rng = &mut ark_std::test_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        println!("seed: {:?}", seed);
       
        let address = [4, 124, 163, 247, 233, 199, 85, 130, 82, 3, 140, 25, 36, 220, 62, 67, 167, 63, 99, 100, 
        184, 45, 134, 47, 53, 126, 204, 66, 26, 135, 123, 184];
    
        let hash_out = B2SPRF::evaluate(&seed, &address).unwrap();
        println!("hash_out : {:?}", hash_out);
    }
    #[test]
    fn test_circuit_without_fx(){
        let rng = &mut ark_std::test_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        
        let mut address = [0u8; 32];
        rng.fill(&mut address);
        
        //hash_out = hash(k);
        let hash_out = B2SPRF::evaluate(&seed, &address).unwrap();

        //把hash_out转成Fr类型
        let field_elements: Vec<Fr> = ToConstraintField::<Fr>::to_field_elements(&hash_out).unwrap();
        println!("field_elements : {:?}", field_elements);

        //E = address + k=seed
        let mut e = [Fr::from(0);32];
        for i in 0..address.len() {
             let t = address[i] as u16 + seed[i] as u16;
             e[i] =Fr::from(t);
        };
        println!("e is {:?}", e);

    
        
        //setup阶段产生公共参数
        let (pk,vk) = 
        Groth16::<Bls12_377>::circuit_specific_setup(DataCircuit{
            address: address,
            k: seed,
            hash_k: hash_out,
        },rng).unwrap();

        //产生证明
        let proof = Groth16::<Bls12_377>::prove(
            &pk,
            DataCircuit{
                address: address,
                k: seed,
                hash_k: hash_out,
            },
            rng,
        ).unwrap();
       
        let a = Fr::from(1);
        let result = Groth16::<Bls12_377>::verify(&vk, &[field_elements[0],field_elements[1],
            e[0],e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9],e[10],e[11],e[12],e[13],e[14],e[15],
            e[16],e[17],e[18],e[19],e[20],e[21],e[22],e[23],e[24],e[25],e[26],e[27],e[28],e[29],e[30],e[31]
            ],
             &proof);
        println!("result  = {:?}", result);
    }
}
