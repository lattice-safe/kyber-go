package kyber

// montgomeryReduce: given a 32-bit integer a, compute
// 16-bit integer congruent to a * R^{-1} mod q, where R=2^16.
func montgomeryReduce(a int32) int16 {
	t := int16(a) * int16(QINV) // wraps modulo 2^16
	return int16((a - int32(t)*Q32) >> 16)
}

// fqmul: Multiplication followed by Montgomery reduction.
func fqmul(a, b int16) int16 {
	return montgomeryReduce(int32(a) * int32(b))
}

// barrettReduce: centered representative mod q in {-(q-1)/2,...,(q-1)/2}.
func barrettReduce(a int16) int16 {
	v := int16((1<<26)/Q32 + 1) // ≈ 20159
	t := int16((int32(v)*int32(a) + (1 << 25)) >> 26)
	return a - t*int16(Q32)
}
