package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidEmbeddedSCTV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	// Just a placeholder for now from https://davidben.net/oid. Don't *actually* deploy this.
	oidOuterCertificateBinding = asn1.ObjectIdentifier{1, 2, 840, 113554, 4, 1, 72585, 123456}

	altInfoListLogID = mustDecodeHex("abdcf1b6ca6af3c91f37f54fbafdbd17e711780d5197d15d0e1e71106d8cb6c5")

	tagVersion    = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()

	oidExtensionSubjectInfoAccess          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	oidExtensionSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidExtensionSubjectKeyId               = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage                   = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName             = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints           = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionNameConstraints            = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtensionCertificatePolicies        = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionPolicyMappings             = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidExtensionPolicyConstraints          = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidExtensionExtendedKeyUsage           = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionInhibitAnyPolicy           = asn1.ObjectIdentifier{2, 5, 29, 54}
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func copyAndSaveASN1Element(out *cryptobyte.Builder, in *cryptobyte.String, saveElem *cryptobyte.String, tag cbasn1.Tag) bool {
	var elem cryptobyte.String
	if !in.ReadASN1Element(&elem, tag) {
		return false
	}
	out.AddBytes(elem)
	*saveElem = elem
	return true
}

func copyASN1Element(out *cryptobyte.Builder, in *cryptobyte.String, tag cbasn1.Tag) bool {
	var unused cryptobyte.String
	return copyAndSaveASN1Element(out, in, &unused, tag)
}

func extractAlternateCertificates(outer *x509.Certificate) ([]*x509.Certificate, error) {
	// Find the embedded SCT extension and require it to be the last one.
	if len(outer.Extensions) == 0 {
		return nil, errors.New("embedded SCT extension not found")
	}
	for _, ext := range outer.Extensions[:len(outer.Extensions)-1] {
		if ext.Id.Equal(oidEmbeddedSCTV1) {
			return nil, errors.New("unexpected embedded SCT extension in the middle of certificate")
		}
	}
	sctExt := outer.Extensions[len(outer.Extensions)-1]
	if !sctExt.Id.Equal(oidEmbeddedSCTV1) {
		return nil, errors.New("embedded SCT extension not found")
	}

	// SignedCertificateTimestampList is encoded as an OCTET STRING inside the
	// extension's value (RFC 6962, Section 3.3).
	extValue := cryptobyte.String(sctExt.Value)
	var sctListBytes, sctList cryptobyte.String
	if !extValue.ReadASN1(&sctListBytes, cbasn1.OCTET_STRING) ||
		!extValue.Empty() ||
		!sctListBytes.ReadUint16LengthPrefixed(&sctList) ||
		sctList.Empty() ||
		!sctListBytes.Empty() {
		return nil, errors.New("could not parse embedded SCT extension")
	}

	var altInfoList cryptobyte.String
	var foundAltInfoList bool
	for !sctList.Empty() {
		var sct cryptobyte.String
		if !sctList.ReadUint16LengthPrefixed(&sct) || sct.Empty() {
			return nil, errors.New("could not parse SCT")
		}
		var version uint8
		if !sct.ReadUint8(&version) {
			return nil, errors.New("could not parse SCT")
		}
		if version != 0 {
			continue
		}
		var id []byte
		var timestamp uint64
		var extensions cryptobyte.String
		var hashAlg, sigAlg uint8
		var signature cryptobyte.String
		if !sct.ReadBytes(&id, 32) ||
			!sct.ReadUint64(&timestamp) ||
			!sct.ReadUint16LengthPrefixed(&extensions) ||
			!sct.ReadUint8(&hashAlg) ||
			!sct.ReadUint8(&sigAlg) ||
			!sct.ReadUint16LengthPrefixed(&signature) ||
			!sct.Empty() {
			return nil, errors.New("could not parse SCT")
		}
		if !bytes.Equal(id, altInfoListLogID) {
			continue
		}
		if foundAltInfoList {
			return nil, errors.New("duplicate AlternateIssuerInfoList SCT")
		}
		if timestamp != 0 || !extensions.Empty() || hashAlg != 0 || sigAlg != 0 {
			return nil, errors.New("invalid AlternateIssuerInfoList SCT")
		}
		altInfoList = signature
		foundAltInfoList = true
	}
	if !foundAltInfoList {
		return nil, errors.New("AlternateIssuerInfoList SCT not found")
	}

	var altInfos cryptobyte.String
	if !altInfoList.ReadASN1(&altInfos, cbasn1.SEQUENCE) || !altInfoList.Empty() {
		return nil, errors.New("could not parse AlternateIssuerInfoList")
	}

	var certs []*x509.Certificate
	for !altInfos.Empty() {
		var altInfo cryptobyte.String
		if !altInfos.ReadASN1(&altInfo, cbasn1.SEQUENCE) {
			return nil, errors.New("could not parse AlternateIssuerInfo")
		}
		cert, err := extractAlternateCertificate(outer, altInfo)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func builderWithErr(f func(*cryptobyte.Builder) error) func(*cryptobyte.Builder) {
	return func(b *cryptobyte.Builder) {
		err := f(b)
		if err != nil {
			b.SetError(err)
		}
	}
}

func readX509Extension(s *cryptobyte.String) (ext cryptobyte.String, oid asn1.ObjectIdentifier, ok bool) {
	if !s.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
		return
	}
	extInner := ext
	if !extInner.ReadASN1(&extInner, cbasn1.SEQUENCE) || !extInner.ReadASN1ObjectIdentifier(&oid) {
		return
	}
	ok = true
	return
}

func isKnownSubjectExtension(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidExtensionSubjectInfoAccess) ||
		oid.Equal(oidExtensionSubjectDirectoryAttributes) ||
		oid.Equal(oidExtensionSubjectKeyId) ||
		oid.Equal(oidExtensionKeyUsage) ||
		oid.Equal(oidExtensionSubjectAltName) ||
		oid.Equal(oidExtensionBasicConstraints) ||
		oid.Equal(oidExtensionNameConstraints) ||
		oid.Equal(oidExtensionCertificatePolicies) ||
		oid.Equal(oidExtensionPolicyMappings) ||
		oid.Equal(oidExtensionPolicyConstraints) ||
		oid.Equal(oidExtensionExtendedKeyUsage) ||
		oid.Equal(oidExtensionInhibitAnyPolicy)
}

func extractAlternateCertificate(outer *x509.Certificate, altInfo cryptobyte.String) (*x509.Certificate, error) {
	outerTBSElem := cryptobyte.String(outer.RawTBSCertificate)
	var outerTBS cryptobyte.String
	if !outerTBSElem.ReadASN1(&outerTBS, cbasn1.SEQUENCE) || !outerTBSElem.Empty() {
		return nil, errors.New("could not parse TBSCertificate")
	}

	// Reconstruct the alternate certificate. The general strategy is that every
	// field is either copied from the outer certificate to the alternate
	// certificate as-is, or it is taken from altInfo, with the overwritten field
	// saved in outerBinding. This implementation (re)parses the TBSCertificate
	// and AlternateIssuerInfo on the fly while rewriting. If you already have
	// them parsed out, you could do that too.
	var altSigAlg cryptobyte.String
	outerBinding := cryptobyte.NewBuilder(nil)
	altCertElem := cryptobyte.NewBuilder(nil)
	altCertElem.AddASN1(cbasn1.SEQUENCE, builderWithErr(func(altCert *cryptobyte.Builder) error {
		altCert.AddASN1(cbasn1.SEQUENCE, builderWithErr(func(altTBS *cryptobyte.Builder) error {
			// For simplicity, just assume X.509v3 rather than deal with an optional
			// version. Also assume issuerUniqueID and subjectUniqueID are omitted.
			// The parser will cleanly fail otherwise.
			if !copyASN1Element(altTBS, &outerTBS, tagVersion) || // version
				!copyASN1Element(outerBinding, &outerTBS, cbasn1.INTEGER) || // serial
				!copyASN1Element(outerBinding, &outerTBS, cbasn1.SEQUENCE) || // sigalg
				!copyASN1Element(outerBinding, &outerTBS, cbasn1.SEQUENCE) { // issuer
				return errors.New("could not parse outer TBSCertificate")
			}
			var commonExts uint64
			var appendExts cryptobyte.String
			if !copyASN1Element(altTBS, &altInfo, cbasn1.INTEGER) || // serial
				!copyAndSaveASN1Element(altTBS, &altInfo, &altSigAlg, cbasn1.SEQUENCE) || // sigalg
				!copyASN1Element(altTBS, &altInfo, cbasn1.SEQUENCE) || // issuer
				!altInfo.ReadASN1Integer(&commonExts) ||
				!altInfo.ReadASN1(&appendExts, cbasn1.SEQUENCE) {
				return errors.New("could not parse AlternateIssuerInfo")
			}
			outerBinding.AddASN1Uint64(commonExts)
			var outerExtsWrapper, outerExts cryptobyte.String
			if !copyASN1Element(altTBS, &outerTBS, cbasn1.SEQUENCE) || // validity
				!copyASN1Element(altTBS, &outerTBS, cbasn1.SEQUENCE) || // subject
				!copyASN1Element(altTBS, &outerTBS, cbasn1.SEQUENCE) || // subjectPublicKeyInfo
				!outerTBS.ReadASN1(&outerExtsWrapper, tagExtensions) ||
				!outerExtsWrapper.ReadASN1(&outerExts, cbasn1.SEQUENCE) ||
				!outerExtsWrapper.Empty() ||
				!outerTBS.Empty() {
				return errors.New("could not parse outer TBSCertificate")
			}
			// Reconstruct extensions.
			altTBS.AddASN1(tagExtensions, func(altExtsWrapper *cryptobyte.Builder) {
				altExtsWrapper.AddASN1(cbasn1.SEQUENCE, builderWithErr(func(altExts *cryptobyte.Builder) error {
					if commonExts >= uint64(len(outer.Extensions)) {
						return errors.New("too many extensions copied")
					}
					for range commonExts {
						if !copyASN1Element(altExts, &outerExts, cbasn1.SEQUENCE) {
							return errors.New("could not parse outer TBSCertificate")
						}
					}
					for !appendExts.Empty() {
						ext, oid, ok := readX509Extension(&appendExts)
						if !ok {
							return errors.New("could not parse AlternateIssuerInfo")
						}
						if isKnownSubjectExtension(oid) {
							return fmt.Errorf("invalid extension %s added in AlternateIssuerInfo", oid)
						}
						altExts.AddBytes(ext)
					}
					// Save all remaining outer extensions in the outer binding, except the SCT.
					outerBinding.AddASN1(cbasn1.SEQUENCE, builderWithErr(func(outerIssuerExts *cryptobyte.Builder) error {
						for {
							ext, oid, ok := readX509Extension(&outerExts)
							if !ok {
								return errors.New("could not parse outer TBSCertificate")
							}
							if isKnownSubjectExtension(oid) {
								return fmt.Errorf("invalid extension %s removed from outer TBSCertificate", oid)
							}
							if oid.Equal(oidEmbeddedSCTV1) {
								if !outerExts.Empty() {
									return errors.New("SCT must be the last extension")
								}
								break
							}
							outerIssuerExts.AddBytes(ext)
						}
						return nil
					}))
					// Append an outer binding extension.
					outerBindingBytes, err := outerBinding.Bytes()
					if err != nil {
						return err
					}
					altExts.AddASN1(cbasn1.SEQUENCE, func(outerBindingExt *cryptobyte.Builder) {
						outerBindingExt.AddASN1ObjectIdentifier(oidOuterCertificateBinding)
						outerBindingExt.AddASN1(cbasn1.OCTET_STRING, func(extValue *cryptobyte.Builder) {
							extValue.AddASN1(cbasn1.SEQUENCE, func(child *cryptobyte.Builder) {
								child.AddBytes(outerBindingBytes)
							})
						})
					})
					return nil
				}))
			})
			return nil
		}))
		altCert.AddBytes(altSigAlg)
		if !copyASN1Element(altCert, &altInfo, cbasn1.BIT_STRING) || !altInfo.Empty() {
			return errors.New("could not parse AlternateIssuerInfo")
		}
		return nil
	}))

	der, err := altCertElem.Bytes()
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func extract(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: %s extract [FILE]", os.Args[0])
	}

	var data []byte
	var err error
	if len(args) == 0 || args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("could not decode PEM certificate")
	}
	outer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	certs, err := extractAlternateCertificates(outer)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s COMMAND [ARGS...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Available commands:\n")
		fmt.Fprintf(os.Stderr, "  extract - Extract alternate certificates from an outer certificate\n")
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(0)
	}

	switch cmd := flag.Arg(0); cmd {
	case "extract":
		if err := extract(flag.Args()[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting certificates: %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized command %q\n", cmd)
		flag.Usage()
		os.Exit(2)
	}
}
