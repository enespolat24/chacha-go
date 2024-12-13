package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// rol32 rotates x left by n bits.
func rol32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// chachaPermute performs the ChaCha permutation on the state array.
func chachaPermute(state []uint32, nrounds int) {
	for i := 0; i < nrounds; i += 2 {
		// Quarter round 1
		state[0] += state[4]
		state[12] = rol32(state[12]^state[0], 16)
		state[1] += state[5]
		state[13] = rol32(state[13]^state[1], 16)
		state[2] += state[6]
		state[14] = rol32(state[14]^state[2], 16)
		state[3] += state[7]
		state[15] = rol32(state[15]^state[3], 16)

		// Quarter round 2
		state[8] += state[12]
		state[4] = rol32(state[4]^state[8], 12)
		state[9] += state[13]
		state[5] = rol32(state[5]^state[9], 12)
		state[10] += state[14]
		state[6] = rol32(state[6]^state[10], 12)
		state[11] += state[15]
		state[7] = rol32(state[7]^state[11], 12)

		// Quarter round 3
		state[0] += state[4]
		state[12] = rol32(state[12]^state[0], 8)
		state[1] += state[5]
		state[13] = rol32(state[13]^state[1], 8)
		state[2] += state[6]
		state[14] = rol32(state[14]^state[2], 8)
		state[3] += state[7]
		state[15] = rol32(state[15]^state[3], 8)

		// Quarter round 4
		state[8] += state[12]
		state[4] = rol32(state[4]^state[8], 7)
		state[9] += state[13]
		state[5] = rol32(state[5]^state[9], 7)
		state[10] += state[14]
		state[6] = rol32(state[6]^state[10], 7)
		state[11] += state[15]
		state[7] = rol32(state[7]^state[11], 7)
	}
}

// hashChaCha generates a hash of the input using ChaCha.
func hashChaCha(input string) ([]byte, error) {
	data := []byte(input)

	// Initial state for ChaCha20
	state := []uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // Constant
		0x01000000, 0x00000000, 0x00000000, 0x00000000, // Key (dummy values)
		0x00000000, 0x00000000, 0x00000000, 0x00000000, // Key (dummy values)
		0x00000000, 0x00000000, 0x00000000, 0x00000001, // Counter & Nonce
	}

	// Incorporate the input into the state
	for i := 0; i < len(data); i++ {
		state[i%16] ^= uint32(data[i]) // XOR input bytes into the state
	}

	result := make([]byte, len(data))

	for i := 0; i < len(data); {
		// Generate a 64-byte keystream block
		stream, err := chachaBlock(state, 20)
		if err != nil {
			return nil, err
		}

		// Determine block size for remaining data
		blockSize := len(data) - i
		if blockSize > 64 {
			blockSize = 64
		}

		// XOR the data with the keystream
		for j := 0; j < blockSize; j++ {
			result[i+j] = data[i+j] ^ stream[j]
		}

		i += blockSize
	}

	return result, nil
}

// chachaBlock generates a 64-byte keystream block from the ChaCha state.
func chachaBlock(state []uint32, nrounds int) ([]byte, error) {
	if len(state) != 16 {
		return nil, errors.New("state must contain exactly 16 32-bit words")
	}

	// Copy the state to avoid modifications
	x := make([]uint32, len(state))
	copy(x, state)

	// Apply the ChaCha permutation
	chachaPermute(x, nrounds)

	// Prepare the keystream block
	stream := make([]byte, 64)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(stream[i*4:], x[i]+state[i])
	}

	// Increment the block counter
	state[12]++

	return stream, nil
}

func main() {
	// Get user input
	var input string
	fmt.Print("Enter string to hash: ")
	fmt.Scanf("%s", &input)

	// Generate hash
	hashed, err := hashChaCha(input)
	if err != nil {
		fmt.Println("Error hashing input:", err)
		return
	}

	// Print the resulting hash in hexadecimal format
	fmt.Printf("Hashed output: %x\n", hashed)
}
