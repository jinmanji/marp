package main

import "testing"

func TestAuthFingerprint(t *testing.T) {
	// 固定值：sha256("Ty9bQ2vLmXp4Rz7Nc1Ha") 的前 12 位（与 README 示例凭据一致）。
	if got := authFingerprint("Ty9bQ2vLmXp4Rz7Nc1Ha"); got != "7b0b1a65ba6c" {
		t.Fatalf("fingerprint = %s", got)
	}
	if len(authFingerprint("x")) != 12 {
		t.Fatal("fingerprint must be 12 hex chars")
	}
	if authFingerprint("a") == authFingerprint("b") {
		t.Fatal("different passwords must produce different fingerprints")
	}
}
