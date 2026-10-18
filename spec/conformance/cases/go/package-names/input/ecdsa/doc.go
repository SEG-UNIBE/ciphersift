// Package ecdsa names EC, but has no finding of family EC: no package-name evidence.
package ecdsa

func Sign(b []byte) []byte { return b }
