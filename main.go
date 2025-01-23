package main

import (
	"fmt"
)

const (
	// Constants for ChaCha20
	Rounds = 20
)

func rotateLeft(v uint32, n uint32) uint32 {
	return (v << n) | (v >> (32 - n))
}

func quarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = rotateLeft(state[d], 16)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = rotateLeft(state[b], 12)

	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = rotateLeft(state[d], 8)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = rotateLeft(state[b], 7)
}

func ChaChaInit(grid *[16]uint32, key *[32]byte, nonce *[8]byte) {
	// ChaCha20 constant "expand 32-byte k"
	grid[0] = 0x61707865
	grid[1] = 0x3320646e
	grid[2] = 0x79622d32
	grid[3] = 0x6b206574

	// 256-bit key
	for i := 0; i < 8; i++ {
		grid[4+i] = uint32(key[4*i]) | uint32(key[4*i+1])<<8 | uint32(key[4*i+2])<<16 | uint32(key[4*i+3])<<24
	}

	// Counter and nonce
	grid[12] = 0 // Counter starts at 0
	grid[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	grid[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	grid[15] = 0 // Additional nonce part (in case of 96-bit nonce, this could vary)
}

func ChaCha20(keystream *[64]byte, grid *[16]uint32) {
	workingState := *grid

	// Perform ChaCha rounds
	for i := 0; i < Rounds; i += 2 {
		// Odd round
		quarterRound(&workingState, 0, 4, 8, 12)
		quarterRound(&workingState, 1, 5, 9, 13)
		quarterRound(&workingState, 2, 6, 10, 14)
		quarterRound(&workingState, 3, 7, 11, 15)

		// Even round
		quarterRound(&workingState, 0, 5, 10, 15)
		quarterRound(&workingState, 1, 6, 11, 12)
		quarterRound(&workingState, 2, 7, 8, 13)
		quarterRound(&workingState, 3, 4, 9, 14)
	}

	// Add initial state to the working state
	for i := 0; i < 16; i++ {
		workingState[i] += grid[i]
	}

	// Serialize output
	for i := 0; i < 16; i++ {
		keystream[4*i] = byte(workingState[i])
		keystream[4*i+1] = byte(workingState[i] >> 8)
		keystream[4*i+2] = byte(workingState[i] >> 16)
		keystream[4*i+3] = byte(workingState[i] >> 24)
	}

	grid[12]++ // Increment counter
}

func main() {
	var chachaGrid [16]uint32
	var keystream [64]byte

	var key [32]byte
	var nonce [8]byte

	// First test case
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nChaCha20   : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: 76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586\n")

	// Second test case
	key[31] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nChaCha20   : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: 4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963\n")

	// Third test case
	key[31] = 0
	nonce[7] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nChaCha20   : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757\n")

	// Fourth test case
	nonce[7] = 0
	nonce[0] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nChaCha20   : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b\n")
}
