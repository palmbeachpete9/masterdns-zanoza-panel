package basecodec

import (
	"crypto/rand"
	"testing"
)

func BenchmarkEncodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeLowerBase36(data)
	}
}

func BenchmarkDecodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	encoded := EncodeLowerBase36(data)
	encodedBytes := []byte(encoded)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeLowerBase36(encodedBytes)
	}
}
