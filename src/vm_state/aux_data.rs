use super::*;

#[derive(Debug, Clone)]
pub struct AuxDataHolder<E: Engine, R: RoundFunction<E, SPONGE_ABSORBTION_WIDTH, SPONGE_STATE_WIDTH>> {
    pub empty_hash_port: AlgebraicHashPort<E>,
    pub hash_and_ports_round_function: R,
}