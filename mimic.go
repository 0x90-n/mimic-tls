package main

import (
	"flag"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"log"
	"net"
	"os"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
	%[1]s [OPTION]...

Description:
	Do a TLS handshake with a host using Google Chrome 100(?) fingeprint
Options:
`, os.Args[0])
	flag.PrintDefaults()
}

var SpecChrome105 = tls.ClientHelloSpec{
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
var SpecGolang = tls.ClientHelloSpec{
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

// https://tlsfingerprint.io/id/fc827c8099ac765f
// OpenSSL 1.1.1 11 Sep 2018 (Library: OpenSSL 1.1.1d  10 Sep 2019)
var SpecOpenSsl = tls.ClientHelloSpec{
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

func test(id string, spec *tls.ClientHelloSpec, host *string, sni *string, skipVerify *bool, timeout *time.Duration) {

	d := net.Dialer{Timeout: *timeout}
	tcpConn, err := d.Dial("tcp", *host)
	if err != nil {
		fmt.Printf("RES %s conn_timeout\n", id)
		log.Printf("%s net.Dial() failed: %+v\n", id, err)
		return
	}
	log.Printf("%s Connected\n", id)

	var tlsConfig tls.Config
	if sni != nil {
		tlsConfig = tls.Config{ServerName: *sni, InsecureSkipVerify: *skipVerify}
	} else {
		// Even though there's an SNI extension below, if we don't provide ServerName,
		// it won't populate and will remove the extension. Neat!
		tlsConfig = tls.Config{InsecureSkipVerify: true}
	}
	// This fingerprint includes feature(s), not fully supported by TLS.
	// uTLS client with this fingerprint will only be able to to talk to servers,
	// that also do not support those features.
	tlsConn := tls.UClient(tcpConn, &tlsConfig, tls.HelloCustom)
	tlsConn.ApplyPreset(spec)

	n, err := tlsConn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", *host)))
	if err != nil {
		fmt.Printf("RES %s handshake_timeout\n", id)
		log.Printf("Error sending: %v\n", err)
		return
	}
	// or tlsConn.Handshake() for better control
	log.Printf("%s Wrote %d bytes\n", id, n)
	//fmt.Printf("Grease: %d\n", tlsConn.HandshakeState.Hello.Raw[7*16+2])

	buf := make([]byte, 500)
	n, err = tlsConn.Read(buf)
	if err != nil {
		fmt.Printf("RES %s read_timeout\n", id)
		log.Printf("Error receiving: %v\n", err)
		return
	}
	log.Printf("%s Read %d bytes\n", id, n)

	fmt.Printf("RES %s allowed\n", id)
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

	addr := fmt.Sprintf("%s:%d", *host, *port)

	var clientHelloSpec tls.ClientHelloSpec
	if *fprint == "chrome-105" {
		clientHelloSpec = SpecChrome105
	} else if *fprint == "go" {
		clientHelloSpec = SpecGolang
	} else if *fprint == "openssl" {
		clientHelloSpec = SpecOpenSsl
	} else {
		log.Fatalf("Error unknown fprint: %s\n", *fprint)
		return
	}

	id := fmt.Sprintf("%s_%s_%s", *host, *sni, *fprint)
	if *nosni {
		sni = nil
	}
	test(id, &clientHelloSpec, &addr, sni, isv, timeout)
}
