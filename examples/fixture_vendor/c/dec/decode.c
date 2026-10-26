/* SYNTHETIC stand-in for c/dec/decode.c (examples only) - NOT the upstream file.
   Shape of the pre-fix block-switch check (N2S-24). */
static BROTLI_INLINE BROTLI_BOOL DecodeBlockTypeAndLength(
    int safe, BrotliDecoderState* s, int tree_type) {
  brotli_reg_t max_block_type = s->num_block_types[tree_type];
  if (max_block_type <= 1) {
    return BROTLI_FALSE;
  }
  return BROTLI_TRUE;
}
