package chacha_go

import "fmt"

// rotates x left n bits.
func rol32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// The ChaCha permutation is a 16-word (512-bit) permutation that mixes the input x.
// The number of rounds is specified by the nrounds parameter.
func chachaPermute(x []uint32, nrounds int) {
	for i := 0; i < nrounds; i += 2 {
		x[0] += x[4]
		x[12] = rol32(x[12]^x[0], 16)
		x[1] += x[5]
		x[13] = rol32(x[13]^x[1], 16)
		x[2] += x[6]
		x[14] = rol32(x[14]^x[2], 16)
		x[3] += x[7]
		x[15] = rol32(x[15]^x[3], 16)

		x[8] += x[12]
		x[4] = rol32(x[4]^x[8], 12)
		x[9] += x[13]
		x[5] = rol32(x[5]^x[9], 12)
		x[10] += x[14]
		x[6] = rol32(x[6]^x[10], 12)
		x[11] += x[15]
		x[7] = rol32(x[7]^x[11], 12)

		x[0] += x[4]
		x[12] = rol32(x[12]^x[0], 8)
		x[1] += x[5]
		x[13] = rol32(x[13]^x[1], 8)
		x[2] += x[6]
		x[14] = rol32(x[14]^x[2], 8)
		x[3] += x[7]
		x[15] = rol32(x[15]^x[3], 8)

		x[8] += x[12]
		x[4] = rol32(x[4]^x[8], 7)
		x[9] += x[13]
		x[5] = rol32(x[5]^x[9], 7)
		x[10] += x[14]
		x[6] = rol32(x[6]^x[10], 7)
		x[11] += x[15]
		x[7] = rol32(x[7]^x[11], 7)
	}
}

func main() {
	fmt.Println("Hello, World!")
}
