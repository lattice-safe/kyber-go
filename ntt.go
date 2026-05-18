package kyber

// Pre-computed zetas in Montgomery domain (from C reference).
var ZETAS = [128]int16{
	-1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
	573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
	1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
	-853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
	-1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
	778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
	603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
	-1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
}

func ntt(r *[N]int16) {
	k := 1
	len_ := 128
	for len_ >= 2 {
		start := 0
		for start < 256 {
			zeta := ZETAS[k]
			k++
			for j := start; j < start+len_; j++ {
				t := fqmul(zeta, r[j+len_])
				r[j+len_] = r[j] - t
				r[j] += t
			}
			start += 2 * len_
		}
		len_ >>= 1
	}
}

func invntt(r *[N]int16) {
	f := int16(1441) // mont^2/128
	k := 127
	len_ := 2
	for len_ <= 128 {
		start := 0
		for start < 256 {
			zeta := ZETAS[k]
			k--
			for j := start; j < start+len_; j++ {
				t := r[j]
				r[j] = barrettReduce(t + r[j+len_])
				r[j+len_] = fqmul(zeta, r[j+len_]-t)
			}
			start += 2 * len_
		}
		len_ <<= 1
	}

	for i := range r {
		r[i] = fqmul(r[i], f)
	}
}

func basemul(r []int16, a []int16, b []int16, zeta int16) {
	r[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0])
	r[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0])
}
