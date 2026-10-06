package tls_test

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtls "github.com/opendatahub-io/odh-platform-utilities/framework/tls"
)

func TestConfigFromProfile_TLS12SetsCipherSuites(t *testing.T) {
	t.Parallel()

	spec := *configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	fn, unsupported := pkgtls.ConfigFromProfile(spec)
	require.NotNil(t, fn)
	assert.Equal(t, []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
	}, unsupported)

	cfg := &tls.Config{}
	fn(cfg)

	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Len(t, cfg.CipherSuites, 6)
	assert.Contains(t, cfg.CurvePreferences, tls.X25519)
	assert.Contains(t, cfg.CurvePreferences, tls.CurveP256)
}

func TestConfigFromProfile_TLS12DropsTLS13Ciphers(t *testing.T) {
	t.Parallel()

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers: []string{
			"TLS_AES_128_GCM_SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
		},
	}
	fn, unsupported := pkgtls.ConfigFromProfile(spec)
	cfg := &tls.Config{}
	fn(cfg)

	assert.Equal(t, []string{"TLS_AES_128_GCM_SHA256"}, unsupported)
	assert.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, cfg.CipherSuites)
}

func TestConfigFromProfile_TLS13LeavesCipherSuitesUnset(t *testing.T) {
	t.Parallel()

	spec := *configv1.TLSProfiles[configv1.TLSProfileModernType]
	fn, unsupported := pkgtls.ConfigFromProfile(spec)
	require.NotNil(t, fn)
	assert.Empty(t, unsupported)

	cfg := &tls.Config{}
	fn(cfg)

	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Empty(t, cfg.CipherSuites)
}

func TestConfigFromProfile_UnsupportedCiphersReported(t *testing.T) {
	t.Parallel()

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES128-GCM-SHA256"},
	}
	fn, unsupported := pkgtls.ConfigFromProfile(spec)
	require.NotNil(t, fn)
	assert.Equal(t, []string{"DHE-RSA-AES128-GCM-SHA256"}, unsupported)

	cfg := &tls.Config{}
	fn(cfg)
	assert.Len(t, cfg.CipherSuites, 1)
}

func TestConfigFromProfile_UnknownMinVersionFloorsToTLS12(t *testing.T) {
	t.Parallel()

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: "VersionTLS99",
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
	}
	fn, _ := pkgtls.ConfigFromProfile(spec)
	cfg := &tls.Config{}
	fn(cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestConfigFromProfile_SkipsUnknownGroups(t *testing.T) {
	t.Parallel()

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		Groups: []configv1.TLSGroup{
			configv1.TLSGroupX25519,
			"not-a-group",
			configv1.TLSGroupSecP256r1MLKEM768,
			configv1.TLSGroupSecP384r1MLKEM1024,
		},
	}
	fn, unsupported := pkgtls.ConfigFromProfile(spec)
	cfg := &tls.Config{}
	fn(cfg)
	assert.Equal(t, []tls.CurveID{tls.X25519, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}, cfg.CurvePreferences)
	assert.Equal(t, []string{"not-a-group"}, unsupported)
}

func TestConfigFromProfile_EmptyGroupsLeaveCurvePreferencesUnset(t *testing.T) {
	t.Parallel()

	spec := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
	}
	fn, _ := pkgtls.ConfigFromProfile(spec)
	cfg := &tls.Config{}
	fn(cfg)
	assert.Nil(t, cfg.CurvePreferences)
}
