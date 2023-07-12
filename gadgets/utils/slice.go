package utils

import (
	"github.com/consensys/gnark/frontend"
)

func Flip[T any](in []T) []T {
	for i := 0; i < len(in)/2; i++ {
		tmp := in[i]
		in[i] = in[len(in)-1-i]
		in[len(in)-1-i] = tmp
	}
	return in
}

func FlipSubSlice[T any](arr []T, chunkSize int) []T {
	if len(arr)%chunkSize != 0 {
		panic("invalid length")
	}
	ret := []T{}
	for i := 0; i < len(arr); i += chunkSize {
		ret = append(ret, Flip(arr[i:i+chunkSize])...)
	}
	return ret
}

func Slice2FVs[T any](a []T) []frontend.Variable {
	vars := []frontend.Variable{}
	for _, v := range a {
		vars = append(vars, v)
	}
	return vars
}
