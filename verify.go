package pkcs7

import (
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

var ErrAttributeTypeNotFound = errors.New("pkcs7: attribute type not in attributes")

var ErrNoSigners = errors.New("pkcs7: Message has no signers")

var ErrNoCertificateForSigner = errors.New("pkcs7: No certificate for signer")

var ErrCertificateMatchedToSigner = errors.New("pkcs7: leaf certificate does not match signer")

// ErrMessageDigestMismatch is returned when the signer data digest does not
// match the computed digest for the contained content
type ErrMessageDigestMismatch struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *ErrMessageDigestMismatch) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

// ErrSigningTimeNotValid is returned when the signing time does not fall
// within the validity time of the certificate
type ErrSigningTimeNotValid struct {
	signingTime time.Time
	notBefore time.Time
	notAfter  time.Time
}

func (err *ErrSigningTimeNotValid) Error() string {
	return fmt.Sprintf("pkcs7: signing time %q is outside of certificate validity %q to %q", 
		err.signingTime.Format(time.RFC3339),
		err.notBefore.Format(time.RFC3339),
		err.notAfter.Format(time.RFC3339))
}

type certPools struct {
	Roots *x509.CertPool
	Intermediates *x509.CertPool
}

// Verify is a wrapper around VerifyWithChain() that initializes an empty
// trust store, effectively disabling certificate verification when validating
// a signature.
func (p7 *PKCS7) Verify() (err error) {
	return p7.VerifyWithChain(nil)
}

// VerifyWithChain checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to one of the roots in the
// truststore. When the PKCS7 object includes the signing time
// authenticated attr it verifies the chain at that time and UTC now
// otherwise.
func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error) {
	return p7.VerifyWithChainAtTime(truststore, time.Time{})
}

// VerifyWithChainAtTime checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to a root in the truststore at
// currentTime. It does not use the signing time authenticated
// attribute.
func (p7 *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err error) {
	intermediates := x509.NewCertPool()
	for _, cert := range(p7.Certificates) {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots: truststore,
		Intermediates: intermediates,
		CurrentTime: currentTime,
	}

	return p7.VerifyWithOpts(opts)
}

// VerifyWithOpts checks the signatures of a PKCS7 object.
//
// It accepts x509.VerifyOptions as a parameter.
// This struct contains a root certificate pool, an intermedate certificate pool, 
// an optional list of EKUs, and an optional time that certificates should be
// checked as being valid during.

// If VerifyOpts.Roots is not nil it verifies the chain of trust of
// the end-entity signer cert to one of the roots in the
// truststore. When the PKCS7 object includes the signing time
// authenticated attr it verifies the chain at that time and UTC now
// otherwise.
func (p7 *PKCS7) VerifyWithOpts(opts x509.VerifyOptions) (err error) {
	// if KeyUsage isn't set, default to ExtKeyUsageAny
	if opts.KeyUsages == nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	if len(p7.Signers) == 0 {
		return ErrNoSigners
	}

	// if opts.CurrentTime is not set, call verifySignature,
	// which will verify the leaf certificate with the current time
	if opts.CurrentTime.IsZero() {
		for _, signer := range p7.Signers {
			if err := verifySignature(p7, signer, opts); err != nil {
				return err
			}
		}
		return nil
	}
	// if opts.CurrentTime is set, call verifySignatureAtTime,
	// which will verify the leaf certificate with opts.CurrentTime
	for _, signer := range p7.Signers {
		if err := verifySignatureAtTime(p7, signer, opts); err != nil {
			return err
		}
	}
	return nil
}

func verifyEKU(cert *x509.Certificate, expectedEKU x509.ExtKeyUsage) error {
	var found bool
	for _, eku := range cert.ExtKeyUsage {
		if eku == expectedEKU {
			found = true
		}
	}
	if !found {
		return errors.New(fmt.Sprintf("certificate must set EKU to %d", expectedEKU))
	}
	return nil
}

func verifySignatureAtTime(p7 *PKCS7, signer signerInfo, opts x509.VerifyOptions) (err error) {
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return ErrNoCertificateForSigner
	}

	signedData, err := verifySignedData(p7.Content, signer)
	if err != nil {
		return err
	}

	if opts.Roots != nil {
		_, err = ee.Verify(opts)
		if err != nil {
			return fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

func verifySignature(p7 *PKCS7, signer signerInfo, opts x509.VerifyOptions) (err error) {
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return ErrNoCertificateForSigner
	}

	signingTime, err := verifySignedTime(ee, signer)
	if err != nil {
		return err
	}
	opts.CurrentTime = signingTime

	return verifySignatureAtTime(p7, signer, opts)
}

func verifySignedData(p7Content []byte, signer signerInfo) ([]byte, error) {
	if len(signer.AuthenticatedAttributes) == 0 {
		return p7Content, nil
	}
	
	// TODO(fullsailor): First check the content type match
	var digest []byte

	err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest)
	if err != nil {
		return nil, err
	}
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(p7Content)
	computed := h.Sum(nil)
	if subtle.ConstantTimeCompare(digest, computed) != 1 {
		return nil, &ErrMessageDigestMismatch{
			ExpectedDigest: digest,
			ActualDigest:   computed,
		}
	}
	signedData, err := marshalAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

func verifySignedTime(ee *x509.Certificate, signer signerInfo) (time.Time, error) {
	signingTime := time.Now().UTC()

	if len(signer.AuthenticatedAttributes) == 0 {
		return signingTime, nil
	}

	err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
	if err != nil {
		return time.Time{}, err
	}

	// signing time found, performing validity check
	if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
		return time.Time{}, &ErrSigningTimeNotValid{
			signingTime: signingTime,
			notBefore: ee.NotBefore,
			notAfter: ee.NotAfter,
		}
	}
	return signingTime, nil
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *x509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if compound.Tag == 4 {
			if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
				return nil, err
			}
		} else {
			content = compound.Bytes
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

// verifyCertChain takes an end-entity certs, a list of potential intermediates and a
// truststore, and built all potential chains between the EE and a trusted root.
//
// When verifying chains that may have expired, currentTime can be set to a past date
// to allow the verification to pass. If unset, currentTime is set to the current UTC time.
func verifyCertChain(ee *x509.Certificate, pools certPools, currentTime time.Time) (chains [][]*x509.Certificate, err error) {
	verifyOptions := x509.VerifyOptions{
		Roots:         pools.Roots,
		Intermediates: pools.Intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = ee.Verify(verifyOptions)
	if err != nil {
		return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}
	return chains, err
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

func getSignatureAlgorithm(digestEncryption, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA1):
		return x509.ECDSAWithSHA1, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512, nil
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSA),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA1),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA512):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.SHA1WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.SHA256WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return x509.SHA384WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return x509.SHA512WithRSA, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSA),
		digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSASHA1):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.DSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.DSAWithSHA256, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP521):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.ECDSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.ECDSAWithSHA256, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return x509.ECDSAWithSHA384, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return x509.ECDSAWithSHA512, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmEDDSA25519):
		return x509.PureEd25519, nil
	default:
		return -1, fmt.Errorf("pkcs7: unsupported algorithm %q",
			digestEncryption.Algorithm.String())
	}
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return ErrAttributeTypeNotFound
}
