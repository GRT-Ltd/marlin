use ark_ec::AffineCurve;
use ark_ec::msm::VariableBaseMSM;
use ark_ff::PrimeField;
use msm_cuda::multi_scalar_mult_arkworks;

/// grt modify msm
pub fn msm<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInt],
) -> G::Projective {

    let str  = if cfg!(feature = "cuda"){
        "GPU"
    }else{
        "CPU"
    };

   let grt_time = start_timer!(|| format!("msm {} len = {}",str , scalars.len()));
    #[cfg(not(feature = "cuda"))]
        let temp = VariableBaseMSM::multi_scalar_mul(bases, scalars);
    #[cfg(feature = "cuda")]
        let temp = multi_scalar_mult_arkworks(bases, scalars);
    end_timer!(grt_time);

    return temp;
}
