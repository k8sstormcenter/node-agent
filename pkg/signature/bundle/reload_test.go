package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writePolicyFile(t *testing.T, dir string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, "trust-policy.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

func newTestReloader(t *testing.T, path, fp string, initial []byte) *PolicyReloader {
	t.Helper()
	r := NewPolicyReloader(path, initial)
	r.resolveRoot = func() (string, bool, error) { return fp, true, nil }
	return r
}

// A policy that changes and verifies is applied.
func TestPolicyReloader_AppliesVerifiedChange(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	first, fp := signPolicyWithFingerprint(t, demoPolicy(), key)
	path := writePolicyFile(t, dir, first)

	r := newTestReloader(t, path, fp, first)
	require.True(t, r.Poll().Unchanged, "identical content must be a no-op")

	// Ship a new policy (same root key) that adds a rule class.
	p2 := demoPolicy()
	p2.RuleClasses = map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{"key:whoever"}, AllowedRuleIDs: []string{"*"}},
	}
	second, _ := signPolicyWithFingerprint(t, p2, key)
	require.NoError(t, os.WriteFile(path, second, 0o600))

	ev := r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied, "a verified change must be applied")
	require.True(t, ev.Applied.RuleSigningEnabled(), "the new policy's ruleClasses must take effect without a restart")
}

// A changed policy signed by the WRONG key is refused; the caller keeps its own.
func TestPolicyReloader_RefusesUnverifiedChange(t *testing.T) {
	dir := t.TempDir()
	good, fp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))
	path := writePolicyFile(t, dir, good)
	r := newTestReloader(t, path, fp, good)

	rogue, _ := signPolicyWithFingerprint(t, demoPolicy(), genKey(t)) // different key
	require.NoError(t, os.WriteFile(path, rogue, 0o600))

	ev := r.Poll()
	require.Error(t, ev.Err, "a policy not signed by the trusted root must be refused")
	require.Nil(t, ev.Applied, "nothing may be applied from an unverifiable artifact")

	// Reported once per distinct content, not every tick.
	require.True(t, r.Poll().Unchanged)
}

// enforce + demo root + no mount is refused on reload too, not just at boot.
func TestPolicyReloader_RefusesDemoRootUnderEnforce(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	p := demoPolicy()
	p.Mode = ModeEnforce
	signed, _ := signPolicyWithFingerprint(t, p, key)
	path := writePolicyFile(t, dir, signed)

	r := NewPolicyReloader(path, nil)
	r.resolveRoot = func() (string, bool, error) { return DemoRootFingerprint, false, nil }
	ev := r.Poll()
	require.Error(t, ev.Err)
	require.Nil(t, ev.Applied)
}
