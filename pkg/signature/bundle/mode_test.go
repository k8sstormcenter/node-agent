package bundle

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The demo root fingerprint constant must equal the fingerprint of the key
// DefaultRootPublicKeyPEM actually embeds, or enforce-mode's demo-key refusal
// silently protects the wrong key.
func TestDemoRootFingerprintMatchesDefault(t *testing.T) {
	fp, err := rootFingerprint()
	require.NoError(t, err)
	require.Equal(t, DemoRootFingerprint, fp,
		"DemoRootFingerprint is out of sync with DefaultRootPublicKeyPEM")
	require.True(t, IsDemoRoot(fp))
	require.False(t, IsDemoRoot("key:0000000000000000000000000000000000000000000000000000000000000000"))
}

func TestEffectiveMode(t *testing.T) {
	require.Equal(t, ModeEnforce, TrustPolicy{Mode: ModeEnforce}.EffectiveMode())
	require.True(t, TrustPolicy{Mode: ModeEnforce}.Enforcing())
	// A mounted policy is never silent: absent or unknown mode -> alert, not off.
	require.Equal(t, ModeAlert, TrustPolicy{}.EffectiveMode())
	require.Equal(t, ModeAlert, TrustPolicy{Mode: "wat"}.EffectiveMode())
	require.False(t, TrustPolicy{}.Enforcing())
}

func TestModeRoundTripsJSON(t *testing.T) {
	in := TrustPolicy{Mode: ModeEnforce, Classes: map[FragmentClass]ClassPolicy{}}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	require.Contains(t, string(b), `"mode":"enforce"`)
	var out TrustPolicy
	require.NoError(t, json.Unmarshal(b, &out))
	require.Equal(t, ModeEnforce, out.Mode)

	// A policy without a mode omits the field and reads back as alert.
	b2, _ := json.Marshal(TrustPolicy{Classes: map[FragmentClass]ClassPolicy{}})
	require.NotContains(t, string(b2), `"mode"`)
}
