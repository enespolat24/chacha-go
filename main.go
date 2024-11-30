package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

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

// chachaBlock generates a 64-byte keystream block from the 16-word state.
func chachaBlock(state []uint32, nrounds int) ([]byte, error) {
	if len(state) != 16 {
		return nil, errors.New("state must have exactly 16 32-bit words")
	}

	// Make a copy of the state to avoid modifying the original state
	x := make([]uint32, len(state))
	copy(x, state)

	chachaPermute(x, nrounds)

	// Prepare the keystream block (64 bytes)
	stream := make([]byte, 64)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(stream[i*4:], x[i]+state[i])
	}

	// Increment the block counter (state[12] in the original code)
	state[12]++

	return stream, nil
}

// hchachaBlock generates a 32-byte block from the 16-word state.
// This is used to generate the subkey for the XChaCha20 cipher.
func hchachaBlock(state []uint32, nrounds int) ([]uint32, error) {
	if len(state) != 16 {
		return nil, errors.New("state must have exactly 16 32-bit words")
	}

	x := make([]uint32, len(state))
	copy(x, state)

	chachaPermute(x, nrounds)

	return append([]uint32(nil), x[0:4]...), nil
}

func main() {
	state := []uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x01000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000001,
	}

	stream, err := chachaBlock(state, 20) // Using 20 rounds (default for ChaCha20)
	if err != nil {
		fmt.Println("Error generating block:", err)
		return
	}

	fmt.Printf("Keystream block: %x\n", stream)

	hcState, err := hchachaBlock(state, 20)
	if err != nil {
		fmt.Println("Error generating HChaCha block:", err)
		return
	}
	fmt.Printf("HChaCha result: %x\n", hcState)
}
