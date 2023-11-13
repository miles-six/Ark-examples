# Ark-examples
Ark 对于初学者 没有一些例子去仿写学习还是很难受的，分别对a * b =c ,y =x^3 + x + 5 ,k = blake2s(b)写了一些约束，并且通过Groth16进行了Prove与验证

值得注意的是：一定要注意使用依赖的版本，0.3 与 0.4系列相差比较大


## 原生约束
通过最原始的加法与乘法门实现电路，enforce_constraints(a:lc()!,b:lc()!,c:lc()!)添加约束

## Var 
在Arkwork各种库里，封装了一些Var，比如FpVar。当调用Fpvar封装好的一些函数，可以忽略掉底层的原生约束，因为已经封装在了函数里面

## Gadget
Gadget个人理解 是一个子电路，封装实现了若干Var，比如ark_crypto_primitives-prf-Blake哈希

## 核心
**要实现一个trait impl<F:Field> ConstraintSynthesizer<F> for Circuit<F>{**
    
    fn generate_constraints(self,cs: ConstraintSystemRef<F>,) 
    -> Result<(), SynthesisError> {
    Ok(())
    }
