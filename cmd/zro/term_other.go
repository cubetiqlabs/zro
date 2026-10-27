//go:build !linux && !darwin

package main

func isTerminal(int) bool                           { return false }
func termSize(int) (int, int)                       { return 80, 24 }
func makeRaw(int) (func(), error)                   { return func() {}, nil }
func watchResize(int, func(int, int)) (stop func()) { return func() {} }
