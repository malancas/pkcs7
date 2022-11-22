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
// authenticated attr verifies the chain at that time and UTC now
// otherwise.
func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error) {
	signingTime := time.Now().UTC()
	return p7.VerifyWithChainAtTime(truststore, signingTime)
}

// VerifyWithChainAtTime checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to a root in the truststore at
// currentTime. It does not use the signing time authenticated
// attribute.
func (p7 *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
		if ee == nil {
			return errors.New("pkcs7: No certificate for signer")
		}

		if err := verifySignature(ee, p7, signer, truststore, currentTime); err != nil {
			return err
		}
	}
	return nil
}

func (p7 *PKCS7) VerifyWithCertPools(pools certPools, leafCert *x509.Certificate, eku x509.ExtKeyUsage) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	if leafCert != nil {
		for _, signer := range p7.Signers {
			if !isCertMatchForIssuerAndSerial(leafCert, signer.IssuerAndSerialNumber) {
				return errors.New("pkcs7: leaf certificate does not match signer")
			}
			signingTime := time.Now().UTC()
			if err := verifySignatureWithCertPools(leafCert, p7, signer, pools, signingTime); err != nil {
				return err
			}
		}
	}
	for _, signer := range p7.Signers {
		ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
		if ee == nil {
			return errors.New("pkcs7: No certificate for signer")
		}
		
		signingTime := time.Now().UTC()
		if err := verifySignatureWithCertPools(ee, p7, signer, pools, signingTime); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(ee *x509.Certificate, p7 *PKCS7, signer signerInfo, truststore *x509.CertPool, signingTime time.Time) (err error) {
	signedData, err := verifySignedData(ee, p7.Content, signer, signingTime)
	if err != nil {
		return err
	}
	if truststore != nil {
		intermediates := x509.NewCertPool()
		for _, intermediate := range p7.Certificates {
			intermediates.AddCert(intermediate)
		}
		pools := certPools {
			Roots: truststore,
			Intermediates: intermediates,
		}

		_, err = verifyCertChain(ee, pools, signingTime)
		if err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

func verifySignatureWithCertPools(ee *x509.Certificate, p7 *PKCS7, signer signerInfo, pools certPools, signingTime time.Time) (err error) {
	signedData, err := verifySignedData(ee, p7.Content, signer, signingTime)
	if err != nil {
		return err
	}
	if pools.Roots != nil && pools.Intermediates != nil {
		_, err = verifyCertChain(ee, pools, signingTime)
		if err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(sigalg, signedData, signer.EncryptedDigest)
}

func verifySignedData(ee *x509.Certificate, p7Content []byte, signer signerInfo, signingTime time.Time) ([]byte, error) {
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
		return nil, &MessageDigestMismatchError{
			ExpectedDigest: digest,
			ActualDigest:   computed,
		}
	}
	signedData, err := marshalAttributes(signer.AuthenticatedAttributes)
	if err != nil {
		return nil, err
	}
	err = unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
	if err == nil {
		// signing time found, performing validity check
		if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
			return nil, fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
				signingTime.Format(time.RFC3339),
				ee.NotBefore.Format(time.RFC3339),
				ee.NotAfter.Format(time.RFC3339))
		}
	}
	return signedData, nil
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
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

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
	return
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
	return errors.New("pkcs7: attribute type not in attributes")
}
