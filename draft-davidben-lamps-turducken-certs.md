---
title: "Smuggled Nested Additional-Issuer Layer (SNAIL) Certificates"
category: std

docname: draft-davidben-lamps-turducken-certs-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "davidben/turducken-certs"
  latest: "https://davidben.github.io/turducken-certs/draft-davidben-lamps-turducken-certs.html"

author:
 -
    fullname: "David Benjamin"
    organization: "Google LLC"
    email: "davidben@google.com"

 -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Cryptic Forest Software
    abbrev: Cryptic Forest
    city: Sioux Lookout, Ontario
    country: Canada
    email: mike@ounsworth.ca

normative:

informative:
  PQ-AUTH-ROADMAP:
    target: https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/
    title: Post-Quantum HTTPS Authentication Roadmap
    author:
    - name: "David Benjamin"
    - name: "Joe DeBlasio"
    date: 2026-02-27

...

--- abstract



This document defines a mechanism to embed one or more additional certification paths within a single certificate that is parseable to a legacy relying party that is unaware of this specification. Each additional certification path certifies the same subject information, but with a different issuer. Rather than a general purpose mechanism, embedded additional certificates are a temporary measure for PKI transitions, such as the post-quantum transition, in PKIs with significant legacy deployments.

--- middle

# Introduction

This document provides a new type of hybrid X.509 certificate {{!RFC5280}} aimed at solving the Post-Quantum Cryptography (PQC) migration problem for Public Key Infrastructures (PKIs) that must simultaneously allow for upgraded clients to drop all legacy trust anchors, even against servers that themselves do not support PQC algorithms, as well as continue to serve non-upgraded clients on those legacy trust anchors. The presented solution involves smuggling an additional certificate path (aka issuer) for the same subject and public key, but signed by a PQC CA, inside the traditional certificate. Unlike other types of hybrids, this one does not allow for multiple subject public keys; only for multiple issuer keys.

This addresses several security and backwards-compatibility goals:

* **Security**: The aspect of a PKI that poses the greatest risk to quantum attack is the trust anchor and Issuing Certificate Authority (CA) keys; therefore these need to be the first to migrate to PQC. A PKI Relying Party consuming end-entity certificates is not fully protected against quantum compromise of legacy trust-anchors until it has removed every legacy trust anchor from its local trust store. The only path to achieving this efficiently is to allow CAs to issue PQ-Rooted certificates to every end entity, even if that end entity does not support PQ and is continuing to use a legacy subject public key.
* **Backwards-compatibility**: In a PKI that must continue to serve non-updated legacy relying parties, end entities must use certificates that continue to chain to the legacy trust anchors. Especially, this must work in the current TLS environment which lacks any reliable mechanism for the client to signal which trust anchors it has.

The only simultaneous solution to these problems is to have a certificate that presents as chaining to the original legacy trust anchor, but which carries a nested, non-critical, extension that provides an additional PQ certification path to a PQ trust anchor.

The WebPKI TLS X.509 certificates is the primary motivation {{PQ-AUTH-ROADMAP}}, but this mechanism may be appropriate to other PKIs that share a similar PQC migration problem.

## Detailed Design Requirements

Forward-compatibility requirements:

1. In order to support upgraded clients in fully removing all legacy trust anchors from their trust stores, the mechanism must be transparent to legacy end entities; I.E. it must be possible to issue a PQ-rooted certificate to an end entity that does is not aware of post-quantum cryptography and does not possess a PQ subject key. This implies that certificate issuance of the new certificate type proceeds exactly as legacy certificate issuance and not require additional enrollment requests, or for the end entity to receive and provision multiple certificates. It also assumes that end entities do not attempt to validate their own certificate path.
2. As a corollary, all subject information -- subject public key, SANs, usage policies, etc -- must be identical across the two certification paths.

Security requirements:

1. The "mixed-algorithm" certificate chain must use PQ signatures in all places except the subject key. This includes trust anchor and issuing CA keys, revocation mechanisms, etc. -- WHAT ABOUT SCTs? ARE WE ASSUMING PQ CT LOGS?
2. The mechanism must be robust to "split views". Consider a relying party that consists of multiple processing layers that will each independently validate the certificate. The machinism must be robust to one layer processing the legacy certification path while a different layer processes the PQ. This requires that all subject information (public key, SANs and other extensions, etc) as well as issuer policies be consistent across the two certification path versions of the certificate; either by structural means that do not allow them to differ, or by a consistency-check mechanism that an upgraded client is required to verify.

Backwards-compatibility requirements:

1. The certificate must be valid to a client that possesses the legacy trust anchor, but is completely unaware of both Post-quantum cryptography, and of the mechanism specified in this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document additionally uses the TLS presentation language defined in {{Section 3 of !RFC9846}}.

## Terminology

Subject:
: The entity being described by a certificate.

Subject Information:
: Fields of the X.509 certificate which describe the end entity and which do not vary across issuers, such as subject name, subject public key, key usage, etc.

Issuer:
: The CA that certified the information in a certificate.

Issuer Information:
: Fields of the X.509 certificate which describe the issuer, or which otherwise must vary by issuer, such as issuer name, CRLDistributionPoints, serial number, signature, etc.

Outer certificate:
: A certificate that embeds one or more additional certificates using the mechanism defined in this document.

Outer CA:
: The CA that issues the outer certificate.

Additional certificate:
: One of the certificates embedded in the outer certificate. An additional certificate certifies the same subject information as the outer certificate, but via a different issuer.

Additional CA:
: A CA that issues one of the additional certificates.

# Overview

Outer and additional certificates are closely related and issued in an integrated process:

* All certificates contain the same subject information, including subjectPublicKeyInfo and subjectAltNames, but they differ in signature and issuer-specific information. The common subject-specific extensions all share an ordering.

* The outer certificate embeds an AdditionalIssuerInfo for each additional certificate. This contains both the signature and issuer-specific information for the additional certificate. It is sufficient to reconstruct the additional certificate.

* Each additional certificate contains an outer certificate binding extension. This contains the issuer-specific fields of the outer certificate, but not the signature. This authenticates the outer certificate's issuer-specific information in relying parties that only trust the additional CA.

## Issuing Certificates

The certificates are issued in the following process. From the perspective of the outer CA, it is analogous to embedding Signed Certificate Timestamps (SCTs) in Certificate Transparency (CT) {{!RFC6962}}. From the perspective of each additional CA, it is analogous to issuing a normal certificate, but with an extra extension included.

1. The outer CA validates the subject information and constructs a TBSCertificate with the validated subject information and issuer fields reflecting the outer CA. It sets `notBefore` and `notAfter` such that the certificate validity would be compatible with each additional CA.

2. For each additional CA, the outer and additional CAs run the following process. The processes for each additional CA MAY run in parallel.

   {:type="a"}
   1. The outer CA requests the additional CA to issue a corresponding additional certificate for this TBSCertificate.

   2. The additional CA validates the subject information. If validation fails, or it is otherwise unable to issue this certificate, including with the same `notBefore` and `notAfter`, it rejects this request.

   3. Otherwise, it constructs a TBSCertificate containing the same subject information. The outer CA's issuer-specific fields are removed and replaced with ones reflecting the additional CA.

   4. The additional CA appends an outer certificate binding extension to the TBSCertificate, containing all the removed outer-CA-specific fields. This authenticates the removed fields to a relying party that only trusts the additional CA.

   5. The additional CA signs this TBSCertificate to issue an additional certificate.

   6. The additional CA extracts the additional certificate's issuer-specific fields and signature. It returns these to the outer CA as an AdditionalIssuerInfo. This contains enough information for the relying party to reconstruct the additional certificate.

3. If the outer CA participates in Certificate Transparency, it additionally signs a precertificate for this TBSCertificate, including the critical poison extension, as described in {{Section 3.1 of !RFC6962}}. The outer CA then requests SCTs from CT logs. This step MAY run in parallel with step 2.

4. The outer CA collects all AdditionalIssuerInfos and SCTs and appends an `id-ce-embeddedSCT-CTv1` extension to its TBSCertificate.

5. The outer CA signs the TBSCertificate to complete the outer certificate.

{{fig-turducken-issuance}} illustrates this process. Although the two issuance processes are now integrated, from the outer CA's perspective, it is analogous to embedding SCTs in CT. From the additional CA's perspective, this is issuing a certificate with a specific extension added.

~~~ aasvg
 CERTIFICATION AUTHORITY A        CERTIFICATION AUTHORITY B
---------------------------      ---------------------------

TBSCertificate                   TBSCertificate
+-----------------+                +-----------------+
|   SUBJECT INFO  |                |   SUBJECT INFO  |
+-----------------+    ------->    +-----------------+
|     A INFO      |                |     B INFO      |
+-----------------+                +-----------------+
                                           +----------------+
                                       |   |     A INFO     |
                                       |   +----------------+
                                       V

                                 Additional Certificate
                                 +-----------------+---+
                                 |   SUBJECT INFO  |   |
                                 +-----------------+ B |
                                 |     B INFO      |   |
                                 +-----------------+ S |
                                 | Outer Cert Bind | I |
                                 |  +--------------+ G |
                                 |  |    A INFO    |   |
Outer Certificate                +--+--------------+---+
+-----------------+---+
|   SUBJECT INFO  |   |                   |
+-----------------+ A |                   |
|     A INFO      |   |                   V
+-----------------+ S |
| SCTs            | I |            "SCT"
|  +--------------+ G |            +--------------+
|  |    B INFO    |   |            |    B INFO    |
+  +--------------+   |   <-----   +--------------+
|  |    B SIG     |   |            |    B SIG     |
+--+--------------+---+            +--------------+
~~~
{: #fig-turducken-issuance title="A diagram of how the additional and outer certificates are issued. A is the outer CA, and B is an additional CA."}

{{certification-authorities}} discusses this in more detail.

## Verifying Certificates

When the certificate subject presents the outer certificate to a relying party, relying parties will attempt to validate one of several certificates:

* Older relying parties that are not aware of this protocol will ignore the unrecognized SCT and validate the outer certificate as usual.

* Newer relying parties will reconstruct the additional certificates and use them as candidate target certificates when building certification paths {{!RFC4158}}.

This allows the same certificate to serve both older relying parties that expect the outer CA, and newer relying parties that expect one of the additional CAs.

{{relying-parties}} discusses this in more detail.

# Certification Authorities

Outer and additional certificates are constrained to share subject information. While the outer CA and each additional CA MAY have different operators, they are expected to coordinate their certificate profiles and issuance processes. Concretely:

The outer and additional certificates MUST have a `version` of v3 and MUST omit `issuerUniqueID` and `subjectUniqueID`. These are preexisting requirements from {{Sections 4.1.2.1 and 4.1.2.8 of !RFC5280}}.

The outer and additional certificates MUST have the same `validity`, `subject`, and `subjectPublicKeyInfo` values.

The outer and additional certificates' `extensions` lists MUST satisfy the following:

* Each extension list MUST consist of, in order, some number of *subject extensions*, some number of *issuer extensions*, and a single final extension. See {{extension-types}} for details.

* The subject extensions across all certificates MUST be equal and appear in the same order.

* The outer certificate's final extension MUST have type `id-ce-embeddedSCT-CTv1`, as described in {{additional-certificate-information}}.

* Each additional certificate's final extension MUST have type `id-pe-outerCertificateBinding`, as described in {{outer-certificate-binding}}.

{{certificate-mismatch}} discusses why these constraints are necessary.

## Extension Types

As discussed in {{certificate-mismatch}}, this document requires outer and additional certificates to certify the same subject information. X.509 does not distinguish between certificate extensions that relate to the subject and those that relate to the issuer.

The registry defined in {{iana-extension-types}} classifies extensions into *subject extensions* and *issuer extensions*.

Broadly, subject extensions are those that define properties of the certificate subject. These are expected to match no matter which CA certifies this information. Subject extensions include:

* `id-ce-subjectKeyIdentifier`, {{Section 4.2.1.2 of !RFC5280}}
* `id-ce-keyUsage`, {{Section 4.2.1.3 of !RFC5280}}
* `id-ce-certificatePolicies`, {{Section 4.2.1.4 of !RFC5280}}
* `id-ce-policyMappings`, {{Section 4.2.1.5 of !RFC5280}}
* `id-ce-subjectAltName`, {{Section 4.2.1.6 of !RFC5280}}
* `id-ce-subjectDirectoryAttributes`, {{Section 4.2.1.8 of !RFC5280}}
* `id-ce-basicConstraints`, {{Section 4.2.1.9 of !RFC5280}}
* `id-ce-nameConstraints`, {{Section 4.2.1.10 of !RFC5280}}
* `id-ce-policyConstraints`, {{Section 4.2.1.11 of !RFC5280}}
* `id-ce-extKeyUsage`, {{Section 4.2.1.12 of !RFC5280}}
* `id-ce-inhibitAnyPolicy`, {{Section 4.2.1.14 of !RFC5280}}
* `id-pe-subjectInfoAccess`, {{Section 4.2.2.2 of !RFC5280}}

Issuer extensions are specific to the certificate issuer. These include:

* `id-ce-authorityKeyIdentifier`, {{Section 4.2.1.1 of !RFC5280}}
* `id-ce-issuerAltName`, {{Section 4.2.1.7 of !RFC5280}}
* `id-ce-cRLDistributionPoints`, {{Section 4.2.1.13 of !RFC5280}}
* `id-ce-freshestCRL`, {{Section 4.2.1.15 of !RFC5280}}
* `id-pe-authorityInfoAccess`, {{Section 4.2.2.1 of !RFC5280}}
* `id-ce-embeddedSCT-CTv1`, {{Appendix B of !RFC9162}}
* `id-ce-transparencyInfo`, {{Appendix B of !RFC9162}}
* `id-pe-outerCertificateBinding`, {{outer-certificate-binding}}

Concretely, an extension is a subject extension if its extension ID appears in the registry with an "Extension Type" column of "Subject". It is an issuer extension if the "Extension Type" column is "Issuer". X.509 is extensible, so the registry cannot be exhaustive. If the extension ID does not appear in the registry, its classification is not yet defined.

Existing CAs and relying parties will not be aware of classifications that postdate them. While a correctly-operated CA will not issue certificates with unrecognized extensions, relying parties process unrecognized non-critical extensions. {{outer-certificate-binding}} discusses the checks performed by a CA, while {{known-subject-extensions}} discusses the checks performed by a relying party.

## Additional Certificate Information

Each additional certificate is described as differences from the outer certificate in an AdditionalIssuerInfo structure. An AdditionalIssuerInfo is defined as follows:

~~~ asn.1
AdditionalIssuerInfo ::= SEQUENCE {
    serialNumber          CertificateSerialNumber,
    signatureAlgorithm    AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                              {SignatureAlgorithms}},
    issuer                Name,
    subjectExtensionCount INTEGER (0..MAX),
    issuerExtensions      SEQUENCE OF Extension{{IssuerExtensions}},
    signatureValue        BIT STRING
}

AdditionalIssuerInfoList ::= SEQUENCE OF AdditionalIssuerInfo

IssuerExtensions EXTENSION ::= {
    ext-AuthorityKeyIdentifier | ext-IssuerAltName |
    ext-CRLDistributionPoints | ext-FreshestCRL |
    ext-AuthorityInfoAccess |
    ext-embeddedSCT-CTv1 | ext-transparencyInfo |
    ext-outerCertificateBinding,
    ...
}
~~~

An AdditionalIssuerInfo's fields are defined as follows:

* `serialNumber` is the additional certificate's serial number.
* `signatureAlgorithm` is the additional certificate's signature algorithm. This value appears in both the TBSCertificate and Certificate structures.
* `issuer` is the additional certificate's issuer name.
* `subjectExtensionCount` is the number of common subject extensions in the two certificates. It MUST be strictly less than the number of extensions in the outer certificate, to exclude the outer certificate's final extension.
* `issuerExtensions` is the list of issuer extensions in the additional certificate, excluding the final `id-pe-outerCertificateBinding` extension. Each extension in this list MUST be an issuer extension.
* `signatureValue` is the additional certificate's signature value. This is a signature over the reconstructed TBSCertificate, not the AdditionalIssuerInfo.

### Signed Certificate Timestamp Encoding

The AdditionalIssuerInfos for each additional certificate are collected in an AdditionalIssuerInfoList, which is embedded in a SignedCertificateTimestamp (SCT) in the outer certificate's `id-ce-embeddedSCT-CTv1` (OID 1.3.6.1.4.1.11129.2.4.2) extension, as defined in  {{Section 3.3 of !RFC6962}}. This extension MUST be the final extension in the outer certificate.

Note: {{!RFC6962}} was obsoleted by {{?RFC9162}}, but the two protocols are incompatible. This document uses some definitions from {{!RFC6962}} for compatibility with existing deployments.

The SCT is formatted as a TransItem ({{Section 4.5 of !RFC9162}}) with a `versioned_type` of `embedded_additional_issuers`, defined below:

~~~ tls-presentation
enum {
    embedded_additional_issuers(TBD3), (0xFFFF)
} VersionedTransType;

struct {
    VersionedTransType versioned_type;
    select (versioned_type) {
        case embedded_additional_issuers:
            opaque additional_issuer_infos<1..2^24-1>;
    } data;
} TransItem;
~~~

The `additional_issuer_infos` field contains the DER encoding of the AdditionalIssuerInfoList.

Note: This structure uses a two-byte version, while the SignedCertificateTimestamp uses a one-byte version. The VersionedTransType type from {{?RFC9162}} reserves 0x0000..0x00FF to avoid overlapping with the `v1(0)` version value from {{?RFC6962}}. The above structure is defined using {{?RFC9162}} to preserve this property and to make use of the registry defined in {{Section 10.2.3 of ?RFC9162}}. The version allocation means it still can and is used in place of a SignedCertificateTimestamp and not the protocols defined in {{?RFC9162}}.

## Outer Certificate Binding

Each additional certificate contains an outer certificate binding extension, defined below:

~~~ asn.1
OuterCertificateBinding ::= SEQUENCE {
    serialNumber          CertificateSerialNumber,
    signatureAlgorithm    AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                              {SignatureAlgorithms}},
    issuer                Name,
    subjectExtensionCount INTEGER (0..MAX),
    issuerExtensions      SEQUENCE OF Extension{{IssuerExtensions}}
}

id-pe-outerCertificateBinding OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) pe(1) TBD2 }

ext-outerCertificateBinding EXTENSION ::= {
    SYNTAX OuterCertificateBinding
    IDENTIFIED BY id-pe-outerCertificateBinding
    CRITICALITY FALSE
}
~~~

The OuterCertificateBinding structure is similar to the AdditionalIssuerInfo, except that it does not contain a `signatureValue` field. It describes the outer certificate, relative to the additional certificate.

* `serialNumber` is the outer certificate's serial number.
* `signatureAlgorithm` is the outer certificate's signature algorithm. This value appears in both the TBSCertificate and Certificate structures.
* `issuer` is the outer certificate's issuer name.
* `subjectExtensionCount` is the number of common subject extensions in the two certificates.
* `issuerExtensions` is the list of issuer extensions in the outer certificate, excluding the final `id-ce-embeddedSCT-CTv1` extension.

The outer certificate binding extension ensures that, even if a relying party only trusts the additional CA, the outer certificate's contents are still authenticated by a CA trusted by the relying party. The additional CA MUST check the OuterCertificateBinding is well-formed before issuing the certificate. In particular:

* The outer certificate binding extension MUST be the final extension in the additional certificate.

* `subjectExtensionCount` MUST be strictly less than the number of extensions in the additional certificate, to exclude the additional certificate's outer certificate binding extension.

* Each extension in the additional certificate, after the first `subjectExtensionCount` extensions, MUST be an issuer extension, as described in {{extension-types}}. That is, the additional certificate can only add issuer extensions.

* Each extension in `issuerExtensions`, critical or not, MUST also be an issuer extension. That is, the additional certificate can only remove issuer extensions.

If the additional certificate does not satisfy these requirements, the additional certificate is misissued. The above requirements apply even if the extension is not in the registry or is not known to the CA.

The relying party performs a different version of this check in {{known-subject-extensions}}, due to the possibility of unrecognized extensions.

# Relying Parties

When verifying a certificate, a relying party checks if the outer certificate's final extension is `id-ce-embeddedSCT-CTv1`. If so, it looks for an SCT formatted as in {{signed-certificate-timestamp-encoding}}. If found, it decodes the SCT's `signature` value as a DER-encoded AdditionalIssuerInfoList structure.

If any AdditionalIssuerInfo has a recognized `issuer`, the relying party reconstructs the additional certificate as described in {{reconstructing-the-additional-certificate}}. If successful, the additional certificate is used as a candidate target certificate when building certification paths {{!RFC4158}}.

If certification path validation ({{Section 6 of !RFC5280}}) succeeds for any path ending at an additional certificate, the relying party accepts the certificate, even if it would otherwise not accept the outer certificate.

## Reconstructing the Additional Certificate

The following procedure reconstructs an additional certificate from the outer certificate and an AdditionalIssuerInfo.

1. Check each of the following. If any check fails, abort this procedure.

   * The outer certificate's `version` is `v3`.
   * The outer certificate's `signatureAlgorithm` and `signature` fields are equal.
   * The outer certificate has no `subjectUniqueID` or `issuerUniqueID` field.
   * The outer certificate has at least `subjectExtensionCount + 1` extensions and the final extension is `id-ce-embeddedSCT-CTv1`.

2. Make a copy of the outer certificate as a Certificate structure.

3. Replace the TBSCertificate's `serialNumber` field with the AdditionalIssuerInfo's `serialNumber`. Let `outerSerialNumber` be the replaced value.

4. Replace the Certificate's `signatureAlgorithm` field and the TBSCertificate's `signature` field with the AdditionalIssuerInfo's `signatureAlgorithm`. Let `outerSignatureAlgorithm` be the replaced value.

5. Replace the TBSCertificate's `issuer` field with the AdditionalIssuerInfo's `issuer`. Let `outerIssuer` be the replaced value.

6. Remove the TBSCertificate's final extension, which will be `id-ce-embeddedSCT-CTv1`.

7. Remove all but the first `subjectExtensionCount` extensions in the TBSCertificate. Let `outerIssuerExtensions` be the removed extensions.

8. Check if `outerIssuerExtensions` and the AdditionalIssuerInfo's `issuerExtensions` contain known subject extensions, as described in {{known-subject-extensions}}. If any are found, abort this procedure.

9. Append the AdditionalIssuerInfo's `issuerExtensions` to the TBSCertificate.

10. Append a non-critical outer certificate binding extension ({{outer-certificate-binding}}) to the TBSCertificate such that:

    * `serialNumber` is `outerSerialNumber`.
    * `signatureAlgorithm` is `outerSignatureAlgorithm`.
    * `issuer` is `outerIssuer`.
    * `subjectExtensionCount` is the AdditionalIssuerInfo's `subjectExtensionCount` value.
    * `issuerExtensions` is `outerIssuerExtensions`.

11. Replace the Certificate's `signatureValue` field with the AdditionalIssuerInfo's `signatureValue`.

## Known Subject Extensions

{{outer-certificate-binding}} places requirements on additional CAs that certify an OuterCertificateBinding. Relying parties are expected to ignore unrecognized non-critical extensions, so a relying party cannot check these requirements in full.

Instead, relying parties SHOULD check that `outerIssuerExtensions`, as computed in {{reconstructing-the-additional-certificate}}, and the AdditionalIssuerInfo's `issuerExtensions` contain no known subject extensions. Relying parties MUST allow unrecognized extensions for purposes of this check. (If the unrecognized extension is critical, it will likely be rejected later during path validation.)

Relying parties are not required to replicate the entire registry in {{iana-extension-types}}. If the relying party does not implement some subject extension, it MAY ignore it in `outerIssuerExtensions` and `issuerExtensions`. If the relying party implements some extension which does not appear in the registry, it MAY ignore it in this check if the extension does not interact with any issuer-specific constraint during path validation.

See {{certificate-mismatch}} for further discussion.

# Deployment Considerations

## Legacy Services

Embedded additional issuers are a temporary transitionary mechanism for deployments where some legacy services do not support multiple certificates. Services that support multiple certificates directly SHOULD NOT use this mechanism. Deployments are RECOMMENDED to enforce this in CAs and relying parties.

For example, in a post-quantum transition for TLS, embedded additional issuers are only applicable to unmodified legacy services that only have traditional end-entity keys. Once a service has a post-quantum end-entity key, it can be assumed to be relatively up-to-date and necessarily maintains separate end-entity keys for both legacy and post-quantum relying parties. Such a service would have no need for embedded additional issuers. Accordingly, in a TLS deployment using embedded additional issuers for a post-quantum transition:

* CAs SHOULD NOT issue embedded additional issuers if the end-entity key is post-quantum.
* Relying parties SHOULD ignore embedded additional issuers if the end-entity key is post-quantum.

This ensures that, when the post-quantum transition is completed, there will be no embedded additional issuers remaining and implementations can remove the supporting logic.

A given deployment SHOULD only deploy embedded additional issuers once, for only one transition. After that transition has completed, the deployment SHOULD have transitioned to a state where certificate holders support multiple certificates.

## Certificate Transparency Log Sizes

In deployments that use Certificate Transparency (CT) {{!RFC6962}}, a direct post-quantum transition risks significantly increasing the sizes of CT logs. ({{!RFC6962}} was obsoleted by {{?RFC9162}}, but the two protocols are incompatible. This document uses the definitions from {{!RFC6962}} for compatibility with existing deployments.) {{IETF124-PLANTS}} estimated an 8.3x size increase from migrating to ML-DSA-44. While {{?I-D.ietf-plants-merkle-tree-certs}} mitigates this, this mechanism risks logging the large AdditionalIssuerInfo structures in CT logs when the outer certificate is logged.

{{signed-certificate-timestamp-encoding}} partially mitigates this by embedding AdditionalIssuerInfo structures in SCTs. The outer certificate's precertificate omits all SCTs and thus the added post-quantum structures. Logged outer certificate precertificates thus do not increase in size. Additional certificates, if using {{?I-D.ietf-plants-merkle-tree-certs}}, will be unaffected by this size increase. However, when the final certificate with embedded SCTs is logged, the AdditionalIssuerInfo will be logged.

To mitigate this, deployments using embedded additional issuers to transition away from a CT-based PKI thus SHOULD permit CT logs to reject logging of any certificates with an embedded AdditionalIssuerInfoList. This will not impact other embedded SCTs, which refer to logged precertificates rather than logged final certificates.

# Security Considerations

## Validation

Although each additional certificate is ultimately encoded relative to the outer certificate, the additional CA's signature is on the reconstructed additional TBSCertificate, so it is still considered to have issued the reconstructed additional certificate. The additional CA MUST perform all checks it would otherwise have performed in the course of issuing a certificate, such as domain validation. Misissuance of an additional certificate remains misissuance.

## Certificate Mismatch

Relying parties process embedded additional issuers during path building and path validation and potentially validate an additional certificate instead of the outer certificate. The service presenting the certificate or, potentially, some other components of the relying party might be unaware that a different target certificate was ultimately validated. This presents a security risk if the component assumes the relying party validated the outer certificate.

If a relying party's path validation component accepted an additional certificate, subsequent access checks in the relying party SHOULD act on the additional certificate instead of the outer certificate. However, this might not be possible in some cases:

* An application's path validation component might be updated independently from the rest of the application.
* Path validation implementations MAY limit additional certificate support to applications that opt in, but this might slow down PKI transitions that use this mechanism.
* A large application might also opt-in, but forget to update some component.

This document further mitigates this risk in two ways:

1. Limiting additional certificates to encoding the same subject information as the outer certificate.
2. Requiring the additional CA to sign over removed or replaced outer certificate fields, via the outer certificate binding extension.

This contrasts with {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}}, which allow the second certificate to differ significantly. There, the application is expected to be fully aware of the second certificate.

If a more general protocol were instead used in this document, path validation might, for example, validate an additional certificate's public key, while the rest of the application acts on a different, unchecked public key in the outer certificate. This would allow an attacker to bypass certificate-based authentication. This is not possible here because additional certificates cannot replace the `subjectPublicKeyInfo` field.

X.509 extensions complicate this mitigation. X.509 does not distinguish between subject and issuer extensions, so this document introduces a classification in {{extension-types}} and {{iana-extension-types}}. However, extensibility introduces the risk that not all components of a system are aware of the classification of every extension.

This is primarily mitigated by the outer certificate binding extension. Except for `id-ce-embeddedSCT-CTv1`, extensions added or removed from the outer certificate are still signed by the additional CA, so relying parties can hold the additional CA responsible for their contents. In particular, {{outer-certificate-binding}} makes the additional CA responsible for ensuring all such extensions are issuer extensions. CAs are expected to not sign unknown extensions, so there is no conflict with extensibility.

However, there are some cases where the relying party constrains the CA. If the additional CA were under, say, a name constraint ({{Section 4.2.1.10 of !RFC5280}}), the relying party could not rely on the additional CA alone to mitigate subjectAltName mismatches. If the additional certificate contained a permitted subjectAltName, while the outer certificate contained an excluded one, a mismatch could bypass the name constraint. {{known-subject-extensions}} recommends that the relying party also check extension classification. Though the relying party might not recognize all extensions, its path validator necessarily recognizes all extensions that it incorporates into path validation.

# IANA Considerations

## PKIX Module Identifier

IANA is requested to add the following entry in the "SMI Security for PKIX Module Identifier" registry {{!RFC7299}}:

| Decimal | Description                          | References |
|---------|--------------------------------------|------------|
| TBD1    | id-mod-embeddedAdditionalIssuers-2026 | [this-RFC] |

## PKIX Certificate Extension

IANA is requested to add the following entry in the "SMI Security for PKIX Certificate Extension" registry {{!RFC7299}}:

| Decimal | Description                   | References |
|---------|-------------------------------|------------|
| TBD2    | id-pe-outerCertificateBinding | [this-RFC] |

## Extension Types for Embedded Additional Issuers {#iana-extension-types}

IANA is requested to add a new registry, "Extension Types for Embedded Additional Issuers", under the top-level registry "Public Key Infrastructure using X.509 (PKIX) Parameters" at <https://www.iana.org/assignments/pkix-parameters>. The registration policy is Specification Required {{!RFC8126}}.

The registry contains the following note:

> See {{extension-types}} and {{certificate-mismatch}} in [this-RFC] for guidance on how to classify extensions for this registry.

The registry initially consists of:

| OID                     | Description                      | Extension Type | References              |
|-------------------------|----------------------------------|----------------|-------------------------|
| 1.3.6.1.4.1.11129.2.4.2 | id-ce-embeddedSCT-CTv1           | Issuer         | [this-RFC], {{RFC9162}} |
| 1.3.6.1.5.5.7.1.1       | id-pe-authorityInfoAccess        | Issuer         | [this-RFC], {{RFC5280}} |
| 1.3.6.1.5.5.7.1.11      | id-pe-subjectInfoAccess          | Subject        | [this-RFC], {{RFC5280}} |
| 1.3.6.1.5.5.7.1.TBD2    | id-pe-outerCertificateBinding    | Issuer         | [this-RFC]              |
| 1.3.101.75              | id-ce-transparencyInfo           | Issuer         | [this-RFC], {{RFC9162}} |
| 2.5.29.9                | id-ce-subjectDirectoryAttributes | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.14               | id-ce-subjectKeyIdentifier       | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.15               | id-ce-keyUsage                   | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.17               | id-ce-subjectAltName             | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.18               | id-ce-issuerAltName              | Issuer         | [this-RFC], {{RFC5280}} |
| 2.5.29.19               | id-ce-basicConstraints           | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.30               | id-ce-nameConstraints            | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.31               | id-ce-cRLDistributionPoints      | Issuer         | [this-RFC], {{RFC5280}} |
| 2.5.29.32               | id-ce-certificatePolicies        | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.33               | id-ce-policyMappings             | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.35               | id-ce-authorityKeyIdentifier     | Issuer         | [this-RFC], {{RFC5280}} |
| 2.5.29.36               | id-ce-policyConstraints          | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.37               | id-ce-extKeyUsage                | Subject        | [this-RFC], {{RFC5280}} |
| 2.5.29.46               | id-ce-freshestCRL                | Issuer         | [this-RFC], {{RFC5280}} |
| 2.5.29.54               | id-ce-inhibitAnyPolicy           | Subject        | [this-RFC], {{RFC5280}} |

## Versioned Transparency Item Types

IANA is requested to add the following entry in the "VersionedTransTypes" registry {{!RFC9162}}:

| Value | Type and Version           | Reference  |
|-------|----------------------------|------------|
| TBD3  | embedded_additional_issuers | [this-RFC] |

--- back

# ASN.1 Module

This module uses structures defined in {{!RFC5912}} and {{!RFC9162}}.

~~~ asn.1
EmbeddedAdditionalIssuers-2026
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-mod(0)
    id-mod-embeddedAdditionalIssuers-2026(TBD1) }

DEFINITIONS IMPLICIT TAGS ::=
BEGIN

IMPORTS
  SIGNATURE-ALGORITHM, AlgorithmIdentifier{}
  FROM AlgorithmInformation-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-algorithmInformation-02(58) }
  Extension{}, EXTENSION
  FROM PKIX-CommonTypes-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkixCommon-02(57) }
  ext-AuthorityKeyIdentifier, ext-IssuerAltName,
  ext-CRLDistributionPoints, ext-FreshestCRL,
  ext-AuthorityInfoAccess
  FROM PKIX1Implicit-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkix1-implicit-02(59) }
  Name, CertificateSerialNumber, SignatureAlgorithms
  FROM PKIX1Explicit-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkix1-explicit-02(51) }
  ext-embeddedSCT-CTv1, ext-transparencyInfo
  FROM CertificateTransparencyV2Module-2021 -- in [RFC9162]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-public-notary-v2(102) }
;

AdditionalIssuerInfo ::= SEQUENCE {
    serialNumber          CertificateSerialNumber,
    signatureAlgorithm    AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                              {SignatureAlgorithms}},
    issuer                Name,
    subjectExtensionCount INTEGER (0..MAX),
    issuerExtensions      SEQUENCE OF Extension{{IssuerExtensions}},
    signatureValue        BIT STRING
}

AdditionalIssuerInfoList ::= SEQUENCE OF AdditionalIssuerInfo

IssuerExtensions EXTENSION ::= {
    ext-AuthorityKeyIdentifier | ext-IssuerAltName |
    ext-CRLDistributionPoints | ext-FreshestCRL |
    ext-AuthorityInfoAccess |
    ext-embeddedSCT-CTv1 | ext-transparencyInfo |
    ext-outerCertificateBinding,
    ...
}

OuterCertificateBinding ::= SEQUENCE {
    serialNumber          CertificateSerialNumber,
    signatureAlgorithm    AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                              {SignatureAlgorithms}},
    issuer                Name,
    subjectExtensionCount INTEGER (0..MAX),
    issuerExtensions      SEQUENCE OF Extension{{IssuerExtensions}}
}

id-pe-outerCertificateBinding OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) pe(1) TBD2 }

ext-outerCertificateBinding EXTENSION ::= {
    SYNTAX OuterCertificateBinding
    IDENTIFIED BY id-pe-outerCertificateBinding
    CRITICALITY FALSE
}

END
~~~

# Acknowledgments
{:numbered="false"}

Thanks to the authors of {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}} for exploring the space of how to represent related certificates. While this document is intentionally more specialized, it has benefited significantly from their work.

Thanks also to Bob Beck and Corey Bonnell for reviewing the document and providing feedback.
