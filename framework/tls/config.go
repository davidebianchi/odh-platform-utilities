package tls

import (
	"crypto/tls"

	configv1 "github.com/openshift/api/config/v1"
	commonTLS "github.com/openshift/controller-runtime-common/pkg/tls"
	ocpcrypto "github.com/openshift/library-go/pkg/crypto"
)

// ConfigFromProfile returns a function that configures a tls.Config from the
// given OpenShift TLSProfileSpec, along with cipher and group names the Go
// crypto/tls stack cannot use for the configured minimum version. The returned
// function is intended for controller-runtime TLSOpts.
//
// CipherSuites are only set when MinVersion is below TLS 1.3, because Go's
// TLS 1.3 implementation does not allow configuring cipher suites.
// See: https://github.com/golang/go/issues/29349
//
// Known Groups are mapped onto CurvePreferences; unknown group names are skipped.
func ConfigFromProfile(profile configv1.TLSProfileSpec) (func(*tls.Config), []string) {
	_, err := ocpcrypto.TLSVersion(string(profile.MinTLSVersion))
	if err != nil {
		profile.MinTLSVersion = configv1.VersionTLS12
	}

	var unsupportedTLS13 []string
	if profile.MinTLSVersion != configv1.VersionTLS13 {
		profile.Ciphers, unsupportedTLS13 = filterTLS13CipherSuites(profile.Ciphers)
	}

	tlsConfig, unsupported := commonTLS.NewTLSConfigFromProfile(profile)
	return tlsConfig, append(unsupported, unsupportedTLS13...)
}

func cipherCode(cipher string) uint16 {
	code, err := ocpcrypto.CipherSuite(cipher)
	if err == nil {
		return code
	}

	ianaCiphers := ocpcrypto.OpenSSLToIANACipherSuites([]string{cipher})
	if len(ianaCiphers) != 1 {
		return 0
	}

	code, err = ocpcrypto.CipherSuite(ianaCiphers[0])
	if err == nil {
		return code
	}

	return 0
}

func filterTLS13CipherSuites(ciphers []string) (filtered, removed []string) {
	for _, cipher := range ciphers {
		code := cipherCode(cipher)
		if isTLS13CipherSuiteID(code) {
			removed = append(removed, cipher)
			continue
		}
		filtered = append(filtered, cipher)
	}

	return filtered, removed
}

// TLS 1.3 cipher suite IDs occupy the 0x1300-0x13ff range.
func isTLS13CipherSuiteID(code uint16) bool {
	return code&0xff00 == 0x1300
}
