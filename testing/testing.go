package testing

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

var test1024Key, test2048Key, test3072Key, test4096Key *rsa.PrivateKey

type TestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

type CertKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *crypto.PrivateKey
}

func UnmarshalTestFixture(testPEMBlock string) TestFixture {
	var result TestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		case "PRIVATE KEY":
			result.PrivateKey, _ = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		}
	}

	return result
}


func CreateTestCertificateByIssuer(name string, issuer *CertKeyPair, sigAlg x509.SignatureAlgorithm, isCA bool) (*CertKeyPair, error) {
	var (
		priv       crypto.PrivateKey
		derCert    []byte
		issuerCert *x509.Certificate
		issuerKey  crypto.PrivateKey
	)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now().Add(-1 * time.Second),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = *issuer.PrivateKey
	}
	switch sigAlg {
	case x509.SHA1WithRSA:
		priv = test1024Key
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA1WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA1
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA1
		}
	case x509.SHA256WithRSA:
		priv = test2048Key
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA256WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.SHA384WithRSA:
		priv = test3072Key
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA384WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.SHA512WithRSA:
		priv = test4096Key
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA512WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA512
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.ECDSAWithSHA1:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA1WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA1
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA1
		}
	case x509.ECDSAWithSHA256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA256WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.ECDSAWithSHA384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA384WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.ECDSAWithSHA512:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA512WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA512
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	case x509.DSAWithSHA1:
		var dsaPriv dsa.PrivateKey
		params := &dsaPriv.Parameters
		err = dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
		if err != nil {
			return nil, err
		}
		err = dsa.GenerateKey(&dsaPriv, rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA1WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA1
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA1
		}
		priv = &dsaPriv
	case x509.PureEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		switch issuerKey.(type) {
		case *rsa.PrivateKey:
			template.SignatureAlgorithm = x509.SHA256WithRSA
		case *ecdsa.PrivateKey:
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case ed25519.PrivateKey:
			template.SignatureAlgorithm = x509.PureEd25519
		case *dsa.PrivateKey:
			template.SignatureAlgorithm = x509.DSAWithSHA256
		}
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}
	if issuer == nil {
		// no issuer given,make this a self-signed root cert
		issuerCert = &template
		issuerKey = priv
	}

	// log.Println("creating cert", name, "issued by", issuerCert.Subject.CommonName, "with sigalg", sigAlg)
	switch priv.(type) {
	case *rsa.PrivateKey:
		switch issuerKey := issuerKey.(type) {
		case rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey)
		case ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey)
		case ed25519.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey)
		case *dsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*rsa.PrivateKey).Public(), issuerKey)
		}
	case *ecdsa.PrivateKey:
		switch issuerKey := issuerKey.(type) {
		case *rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey)
		case *ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey)
		case ed25519.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey)
		case *dsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*ecdsa.PrivateKey).Public(), issuerKey)
		}
	case ed25519.PrivateKey:
		switch issuerKey := issuerKey.(type) {
		case *rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(ed25519.PrivateKey).Public(), issuerKey)
		case *ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(ed25519.PrivateKey).Public(), issuerKey)
		case ed25519.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(ed25519.PrivateKey).Public(), issuerKey)
		case *dsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(ed25519.PrivateKey).Public(), issuerKey)
		}
	case *dsa.PrivateKey:
		pub := &priv.(*dsa.PrivateKey).PublicKey
		switch issuerKey := issuerKey.(type) {
		case *rsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, pub, issuerKey)
		case *ecdsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*dsa.PublicKey), issuerKey)
		case ed25519.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(dsa.PublicKey), issuerKey)
		case *dsa.PrivateKey:
			derCert, err = x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.(*dsa.PublicKey), issuerKey)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(derCert) == 0 {
		return nil, fmt.Errorf("no certificate created, probably due to wrong keys. types were %T and %T", priv, issuerKey)
	}
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, err
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &CertKeyPair{
		Certificate: cert,
		PrivateKey:  &priv,
	}, nil
}
