package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/sys/cpu"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
	%[1]s [OPTION]...

Description:
	Do a TLS handshake with a host using different TLS fingeprints
Options:
`, os.Args[0])
	flag.PrintDefaults()
}

func specChrome62() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS12,
		TLSVersMin: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{0x00}, // compressionNone
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1},
			},
			&tls.StatusRequestExtension{},
			&tls.SCTExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.FakeChannelIDExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0x00}}, // pointFormatUncompressed
			&tls.SupportedCurvesExtension{[]tls.CurveID{tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
		GetSessionID: sha256.Sum256,
	}
}

func specChrome105() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			//&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{[]uint8{
				tls.PskModeDHE,
			}},
			&tls.SupportedVersionsExtension{[]uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
				tls.CertCompressionBrotli,
			}},
			&tls.GenericExtension{Id: 0x4469}, // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
}

func specGolang() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.StatusRequestExtension{},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.PSSWithSHA256,
				tls.ECDSAWithP256AndSHA256,
				0x0807,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PKCS1WithSHA1,
				tls.ECDSAWithSHA1,
			}},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SCTExtension{},
			&tls.SupportedVersionsExtension{[]uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.X25519},
			}},
		},
	}
}

// https://tlsfingerprint.io/id/fc827c8099ac765f
// OpenSSL 1.1.1 11 Sep 2018 (Library: OpenSSL 1.1.1d  10 Sep 2019)
func specOpenssl() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			0x009f,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			0xccaa,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			0x009e,
			tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
			0x006b,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			0x0067,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			0x0039,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			0x0033,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			0x00ff,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
				0x01,
				0x02,
			}},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				0x001e,
				tls.CurveP521,
				tls.CurveP384,
			}},
			&tls.SessionTicketExtension{},
			&tls.GenericExtension{Id: 0x0016}, // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				0x0807,
				0x0808,
				0x0809,
				0x080a,
				0x080b,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				0x0303,
				tls.ECDSAWithSHA1,
				0x0301,
				tls.PKCS1WithSHA1,
				0x0302,
				0x0202,
				0x0402,
				0x0502,
				0x0602,
			}},
			&tls.SupportedVersionsExtension{[]uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			}},
			&tls.PSKKeyExchangeModesExtension{[]uint8{
				tls.PskModeDHE,
			}},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.X25519},
			}},
		},
	}
}

var (
	once                        sync.Once
	varDefaultCipherSuites      []uint16
	varDefaultCipherSuitesTLS13 []uint16
)

func getCipherSuites() []uint16 {
	var topCipherSuites []uint16

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		// hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)
		hasGCMAsmS390X = false // [UTLS: couldn't be bothered to make it work, we won't use it]

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)

	if hasGCMAsm {
		// If AES-GCM hardware is provided then prioritise AES-GCM
		// cipher suites.
		topCipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		}
	} else {
		// Without AES-GCM hardware, we put the ChaCha20-Poly1305
		// cipher suites first.
		topCipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		}
		varDefaultCipherSuitesTLS13 = []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		}
	}
	return topCipherSuites
}

func shuffleSuites(cipherSuites []uint16, r1 *rand.Rand) []uint16 {

	shuffled := make([]uint16, len(cipherSuites))
	copy(shuffled, cipherSuites)
	r1.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}

func FlipWeightedCoin(weight float64, r1 *rand.Rand) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(r1.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

func removeRC4Ciphers(s []uint16) []uint16 {
	// removes elements in place
	sliceLen := len(s)
	for i := 0; i < sliceLen; i++ {
		cipher := s[i]
		if cipher == tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ||
			cipher == tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA ||
			cipher == tls.TLS_RSA_WITH_RC4_128_SHA {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func removeRandomCiphers(r1 *rand.Rand, s []uint16, maxRemovalProbability float64) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float64(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if FlipWeightedCoin(maxRemovalProbability*float64(i)/floatLen, r1) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}

func specRandom() tls.ClientHelloSpec {

	p := tls.ClientHelloSpec{}
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	var WithALPN bool
	if r1.Int()%2 == 0 {
		WithALPN = true
	} else {
		WithALPN = false
	}

	p.CipherSuites = make([]uint16, len(getCipherSuites()))
	copy(p.CipherSuites, getCipherSuites())
	shuffledSuites := shuffleSuites(p.CipherSuites, r1)

	if FlipWeightedCoin(0.4, r1) {
		p.TLSVersMin = tls.VersionTLS10
		p.TLSVersMax = tls.VersionTLS13
		tls13ciphers := make([]uint16, len(varDefaultCipherSuitesTLS13))
		copy(tls13ciphers, varDefaultCipherSuitesTLS13)
		r1.Shuffle(len(tls13ciphers), func(i, j int) {
			tls13ciphers[i], tls13ciphers[j] = tls13ciphers[j], tls13ciphers[i]
		})
		// appending TLS 1.3 ciphers before TLS 1.2, since that's what popular implementations do
		shuffledSuites = append(tls13ciphers, shuffledSuites...)

		// TLS 1.3 forbids RC4 in any configurations
		shuffledSuites = removeRC4Ciphers(shuffledSuites)
	} else {
		p.TLSVersMin = tls.VersionTLS10
		p.TLSVersMax = tls.VersionTLS12
	}

	p.CipherSuites = removeRandomCiphers(r1, shuffledSuites, 0.4)

	sni := tls.SNIExtension{}
	sessionTicket := tls.SessionTicketExtension{}

	sigAndHashAlgos := []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.PKCS1WithSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.PKCS1WithSHA384,
		tls.PKCS1WithSHA1,
		tls.PKCS1WithSHA512,
	}

	if FlipWeightedCoin(0.63, r1) {
		sigAndHashAlgos = append(sigAndHashAlgos, tls.ECDSAWithSHA1)
	}
	if FlipWeightedCoin(0.59, r1) {
		sigAndHashAlgos = append(sigAndHashAlgos, tls.ECDSAWithP521AndSHA512)
	}
	if FlipWeightedCoin(0.51, r1) || p.TLSVersMax == tls.VersionTLS13 {
		// https://tools.ietf.org/html/rfc8446 says "...RSASSA-PSS (which is mandatory in TLS 1.3)..."
		sigAndHashAlgos = append(sigAndHashAlgos, tls.PSSWithSHA256)
		if FlipWeightedCoin(0.9, r1) {
			// these usually go together
			sigAndHashAlgos = append(sigAndHashAlgos, tls.PSSWithSHA384)
			sigAndHashAlgos = append(sigAndHashAlgos, tls.PSSWithSHA512)
		}
	}

	r1.Shuffle(len(sigAndHashAlgos), func(i, j int) {
		sigAndHashAlgos[i], sigAndHashAlgos[j] = sigAndHashAlgos[j], sigAndHashAlgos[i]
	})
	sigAndHash := tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAndHashAlgos}

	status := tls.StatusRequestExtension{}
	sct := tls.SCTExtension{}
	ems := tls.UtlsExtendedMasterSecretExtension{}
	points := tls.SupportedPointsExtension{SupportedPoints: []byte{0x00}}

	curveIDs := []tls.CurveID{}
	if FlipWeightedCoin(0.71, r1) || p.TLSVersMax == tls.VersionTLS13 {
		curveIDs = append(curveIDs, tls.X25519)
	}
	curveIDs = append(curveIDs, tls.CurveP256, tls.CurveP384)
	if FlipWeightedCoin(0.46, r1) {
		curveIDs = append(curveIDs, tls.CurveP521)
	}

	curves := tls.SupportedCurvesExtension{curveIDs}

	padding := tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}
	reneg := tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}

	p.Extensions = []tls.TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if WithALPN {
		alpn := tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
		p.Extensions = append(p.Extensions, &alpn)
	}

	if FlipWeightedCoin(0.62, r1) || p.TLSVersMax == tls.VersionTLS13 {
		// always include for TLS 1.3, since TLS 1.3 ClientHellos are often over 256 bytes
		// and that's when padding is required to work around buggy middleboxes
		p.Extensions = append(p.Extensions, &padding)
	}
	if FlipWeightedCoin(0.74, r1) {
		p.Extensions = append(p.Extensions, &status)
	}
	if FlipWeightedCoin(0.46, r1) {
		p.Extensions = append(p.Extensions, &sct)
	}
	if FlipWeightedCoin(0.75, r1) {
		p.Extensions = append(p.Extensions, &reneg)
	}
	if FlipWeightedCoin(0.7, r1) {
		p.Extensions = append(p.Extensions, &ems)
	}
	if p.TLSVersMax == tls.VersionTLS13 {
		ks := tls.KeyShareExtension{[]tls.KeyShare{
			{Group: tls.X25519}, // the key for the group will be generated later
		}}
		if FlipWeightedCoin(0.25, r1) {
			// do not ADD second keyShare because crypto/tls does not support multiple ecdheParams
			// TODO: add it back when they implement multiple keyShares, or implement it oursevles
			// ks.KeyShares = append(ks.KeyShares, KeyShare{Group: CurveP256})
			ks.KeyShares[0].Group = tls.CurveP256
		}
		pskExchangeModes := tls.PSKKeyExchangeModesExtension{[]uint8{1}}
		supportedVersionsExt := tls.SupportedVersionsExtension{
			Versions: makeSupportedVersions(p.TLSVersMin, p.TLSVersMax),
		}
		p.Extensions = append(p.Extensions, &ks, &pskExchangeModes, &supportedVersionsExt)

		// Randomly add an ALPS extension. ALPS is TLS 1.3-only and may only
		// appear when an ALPN extension is present
		// (https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-3).
		// ALPS is a draft specification at this time, but appears in
		// Chrome/BoringSSL.
		if WithALPN {

			// ALPS is a new addition to generateRandomizedSpec. Use a salted
			// seed to create a new, independent PRNG, so that a seed used
			// with the previous version of generateRandomizedSpec will
			// produce the exact same spec as long as ALPS isn't selected.
			/*
				r, err := tls.newPRNGWithSaltedSeed(seed, "ALPS")
				if err != nil {
					return p, err
				}
			*/
			if FlipWeightedCoin(0.33, r1) {
				// As with the ALPN case above, default to something popular
				// (unlike ALPN, ALPS can't yet be specified in uconn.config).
				alps := &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"http/1.1"}}
				p.Extensions = append(p.Extensions, alps)
			}
		}

		// TODO: randomly add DelegatedCredentialsExtension, once it is
		// sufficiently popular.
	}
	r1.Shuffle(len(p.Extensions), func(i, j int) {
		p.Extensions[i], p.Extensions[j] = p.Extensions[j], p.Extensions[i]
	})

	return p
}

type Job struct {
	Host   string
	Sni    string
	Fprint string
	Port   int
}

func (j *Job) Str() string {
	return fmt.Sprintf("%s_%s_%s", j.Host, j.Sni, j.Fprint)
}

func (j *Job) ClientHelloSpec() (clientHelloSpec tls.ClientHelloSpec) {
	//var clientHelloSpec tls.ClientHelloSpec
	if j.Fprint == "chrome-105" {
		clientHelloSpec = specChrome105()
	} else if j.Fprint == "chrome-62" {
		clientHelloSpec = specChrome62()
	} else if j.Fprint == "go" {
		clientHelloSpec = specGolang()
	} else if j.Fprint == "openssl" {
		clientHelloSpec = specOpenssl()
	} else if j.Fprint == "random" {
		clientHelloSpec = specRandom()
	} else {
		log.Fatalf("Error unknown fprint: %s\n", j.Fprint)
		clientHelloSpec = tls.ClientHelloSpec{} // nil
	}
	return
}

func test(job Job, skipVerify bool, timeout time.Duration) {

	// Get the spec first so if it's not a real one, we can exit early
	clientHelloSpec := job.ClientHelloSpec()

	// Connect to TCP
	d := net.Dialer{Timeout: timeout}
	tcpConn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", job.Host, job.Port))
	if err != nil {
		fmt.Printf("RES %s conn_timeout\n", job.Str())
		log.Printf("%s net.Dial() failed: %+v\n", job.Str(), err)
		return
	}
	log.Printf("%s Connected\n", job.Str())

	err = tcpConn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		log.Printf("%s setReadDeadline failed: %+v\n", job.Str(), err)
		return
	}

	// Setup TLS
	var tlsConfig tls.Config
	if job.Sni != "" {
		tlsConfig = tls.Config{ServerName: job.Sni, InsecureSkipVerify: skipVerify}
	} else {
		// Even though there's an SNI extension below, if we don't provide ServerName,
		// it won't populate and will remove the extension. Neat!
		tlsConfig = tls.Config{InsecureSkipVerify: true}
	}
	tlsConn := tls.UClient(tcpConn, &tlsConfig, tls.HelloCustom)

	// Apply our custom TLS client hello
	tlsConn.ApplyPreset(&clientHelloSpec)

	// Handshake / write bytes
	n, err := tlsConn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", job.Host)))
	if err != nil {
		fmt.Printf("RES %s handshake_timeout\n", job.Str())
		log.Printf("%s Error sending: %v\n", job.Str(), err)
		return
	}
	// or tlsConn.Handshake() for better control
	log.Printf("%s Wrote %d bytes\n", job.Str(), n)
	//fmt.Printf("Grease: %d\n", tlsConn.HandshakeState.Hello.Raw[7*16+2])

	// Read back something
	buf := make([]byte, 500)
	n, err = tlsConn.Read(buf)
	if err != nil {
		fmt.Printf("RES %s read_timeout\n", job.Str())
		log.Printf("Error receiving: %v\n", err)
		return
	}
	log.Printf("%s Read %d bytes\n", job.Str(), n)

	fmt.Printf("RES %s allowed\n", job.Str())
}

func worker(id int, jobs chan Job, timeout time.Duration) {
	for job := range jobs {
		log.Printf("worker %d testing %s\n", id, job.Str())

		test(job, true, timeout)
		log.Printf("worker %d done\n", id)
	}
}

func main() {
	flag.Usage = usage
	host := flag.String("host", "tlsfingerprint.io", "Host to connect to")
	port := flag.Int("port", 443, "Port to connect to on host")
	sni := flag.String("sni", "", "Servername indiciation extension to send (use -nosni for none). Defaults to host if empty")
	fprint := flag.String("fprint", "chrome-105", "Fingerprint to send. Currently supported: chrome-105, go, openssl")
	nosni := flag.Bool("nosni", false, "Provide if you don't want to send an SNI")
	isv := flag.Bool("insecureSkipVerify", false, "Set if you want to not check certs")
	timeout := flag.Duration("timeout", 6*time.Second, "timeout value of TCP connections.")
	logFile := flag.String("log", "", "log to file.  (default stderr)")
	stdin := flag.Bool("stdin", false, "Set if you are providing a list of domains on stdin. We will try 3*n*n connections, for each combination of domain, sni, and fprint")
	workers := flag.Int("worker", 50, "number of workers in parallel")
	flag.Parse()

	// log, intentionally make it blocking to make sure it got
	// initiliazed before other parts using it
	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			log.Panicln("failed to open log file", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	if *sni == "" {
		sni = host
	}

	if *nosni {
		*sni = ""
	}

	if *stdin {
		var wg sync.WaitGroup
		jobs := make(chan Job, *workers*10)

		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				worker(w, jobs, *timeout)
			}(w)
		}

		var domains []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			domains = append(domains, line)
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
		}

		for _, h := range domains {
			for _, s := range domains {
				for _, fp := range []string{"go", "openssl", "chrome-105", "chrome-62", "random"} {
					job := Job{Host: h, Sni: s, Fprint: fp, Port: 443}
					jobs <- job
				}
			}
		}
		close(jobs)

		wg.Wait()

	} else {
		// Just one
		job := Job{Host: *host, Sni: *sni, Fprint: *fprint, Port: *port}
		test(job, *isv, *timeout)
	}
}
