---
title: "Embedded Alternate Issuer Certificates"
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
    ins: C. Bonnell
    fullname: Corey Bonnell
    organization: TurboLight Solutions, LLC
    email: corey.bonnell@turbolightsolutions.com

 -
    ins: J. Gray
    fullname: John Gray
    organization: Entrust
    email: john.gray@entrust.com

 -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Cryptic Forest Software
    abbrev: Cryptic Forest
    city: Sioux Lookout, Ontario
    country: Canada
    email: mike@ounsworth.ca

normative:
  CABF-EV:
    target: https://cabforum.org/working-groups/server/extended-validation/documents/CA-Browser-Forum-EV-Guidelines-2.0.4.pdf
    title: Guidelines for the Issuance and Management of Extended Validation Certificates
    author:
    - org: CA/Browser Forum
    date: 2026-08-13

informative:
  PQ-AUTH-ROADMAP:
    target: https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/
    title: Post-Quantum HTTPS Authentication Roadmap
    author:
    - name: "David Benjamin"
    - name: "Joe DeBlasio"
    date: 2026-02-27

  IETF126-PQ-AUTH:
    target: https://datatracker.ietf.org/meeting/126/materials/slides-126-saag-post-quantum-authentication-beating-the-s-curve-00
    title: "Post-Quantum Authentication: Beating the S-Curve"
    author:
    - name: "David Benjamin"
    date: 2026-07-24

  IETF124-PLANTS:
    target: https://datatracker.ietf.org/meeting/124/materials/slides-124-plants-solution-space-and-dispatched-work-00.pdf
    title: "PLANTS BoF: Solution Space and Dispatched Work"
    author:
    - name: "David Benjamin"
    date: 2025-11-04

...

--- abstract

This document defines a mechanism to embed one or more alternate certificates within a single outer certificate. The outer certificate remains parseable to a legacy relying party that is unaware of this specification. Each alternate certificate certifies the same subject information, but with a different issuer. This can be used to help TLS on the Web transition securely to post-quantum authentication, as well as other PKI transitions with similar constraints.

--- middle

# Introduction

In transitioning a Public Key Infrastructure (PKI) to post-quantum cryptography, it is necessary to reconfigure relying parties to reject legacy trust anchors before cryptographically-relevant quantum computers (CRQCs) become readily available. Otherwise, provisioning a service with a post-quantum certificate does not prevent downgrade attacks since an attacker equipped with a CRQC can attack any trust anchor that the relying party still trusts in order to forge a trusted certificate, not necessarily the one that issued the legitimate certificate. The service's choice of CA does not impact this attack, only the relying party's trust anchors.

Some applications, such as TLS on the Web, have constraints that make this particularly challenging:

* Upgraded relying parties must continue to connect to legacy services that do not yet support post-quantum algorithms. Waiting for services to universally become post-quantum-capable will take time.

* Relying parties support enough services that out-of-band configuration of which services have migrated to post-quantum is impractical.

* Services must themselves continue to support legacy relying parties that do not support post-quantum algorithms or trust anchors.

* In addition to lacking post-quantum algorithms, some legacy services are also unable to configure and select between multiple certificates based on trust anchor or CA signature, which precludes a solution whereby services are automatically issued separate traditional and PQ-rooted-traditional certificate chains.

{{PQ-AUTH-ROADMAP}} and {{IETF126-PQ-AUTH}} discuss how, for these applications, it is sufficient to migrate to a state where:

1. Legacy services serve certificates with post-quantum issuers, even if the end entity keys are still traditional. This is known as a *post-quantum opt-out certificate*.

2. Upgraded relying parties only accept post-quantum issuers, but accept both post-quantum and traditional end-entity keys.

A post-quantum opt-out certificate is a quantum-resistant proof that the service has authorized a traditional end entity key for upgraded relying parties. It is expected that only services that are not yet post-quantum-capable will authorize such certificates. A securely-configured post-quantum-capable service would authorize only its post-quantum key with post-quantum issuers, leaving its traditional key for traditional issuers and legacy relying parties.

This issuer-side transition thus protects post-quantum services from downgrade, while remaining compatible with legacy services. However, the final two constraints prevent one from simply replacing every legacy service's certificate on renewal, because the legacy services will lose compatibility with legacy relying parties who do not have, or are incapable of processing, a post-quantum certification path and trust anchor.

This document solves this by providing a mechanism to embed the post-quantum opt-out certificate into a legacy certificate in a way that will be ignored by legacy clients unaware of this specification. This meets the security goals of delivering the post-quantum opt-out signal to updated relying parties, while still presenting a compatible certificate to unmodified legacy relying parties. The embedding construction is also designed to meet two other requirements:

* It avoids increasing the size of logged precertificates in Certificate Transparency (CT), as described in {{certificate-transparency-log-sizes}}.
* It aims to mitigate security risks of mismatched certificate contents between the outer and alternate certificates, as described in {{certificate-mismatch}}.

While the Web PKI is the primary motivator, this mechanism may be appropriate for other PKIs with similar post-quantum migration constraints, as well as other similarly-constrained issuer-side PKI transitions. In all cases, however, this is a temporary transitionary tool until services can deploy multiple certificates directly. {{legacy-services}} discusses this in more detail.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document additionally uses the TLS presentation language defined in {{Section 3 of !RFC9846}}.

## Terminology

Subject:
: The entity being described by a certificate.

Issuer:
: The CA that certified the information in a certificate.

Outer certificate:
: A certificate that embeds one or more alternate certificates using the mechanism defined in this document.

Certification Authority (CA):
: The (name, key) tuple representing a certificate issuer.

Outer CA:
: The CA that issues the outer certificate.

Alternate certificate:
: One of the certificates embedded in the outer certificate. An alternate certificate certifies the same subject information as the outer certificate, but via a different issuer.

Alternate CA:
: A CA that issues one of the alternate certificates.

Post-quantum opt-out certificate:
: An end-entity certificate with a traditional subject key and post-quantum issuer. {{PQ-AUTH-ROADMAP}} embeds post-quantum opt-out certificates as alternate certificates in a fully traditional outer certificate. Other applications might issue and deploy them independently, without using this specification.

# Overview

Outer and alternate certificates are closely related and issued in an integrated process:

* All certificates contain the same subject information, including `subjectPublicKeyInfo` and `subjectAltName`, but they differ in signature and issuer-specific information. The common subject-specific extensions all share an ordering.

* The outer certificate embeds an AlternateIssuerInfo for each alternate certificate. This contains both the signature and issuer-specific information for the alternate certificate. It is sufficient to reconstruct the alternate certificate.

* Each alternate certificate contains an outer certificate binding extension. This contains the issuer-specific fields of the outer certificate, but not the signature. This authenticates the outer certificate's issuer-specific information in relying parties that only trust the alternate CA.

## Issuing Certificates

After subject information is validated according to the policies of each CA involved, the certificates are issued in the following process:

1. The outer CA constructs an initial TBSCertificate with the validated subject information and issuer fields reflecting the outer CA. It sets `notBefore` and `notAfter` such that the certificate validity would be compatible with each alternate CA.

2. For each alternate CA, run the following steps. The steps for each alternate CA MAY run in parallel.

   {:type="a"}
   1. The alternate CA constructs a TBSCertificate based on the outer CA's initial TBSCertificate. The outer CA's issuer-specific fields are removed and replaced with ones reflecting the alternate CA.

   2. The alternate CA appends an outer certificate binding extension to its TBSCertificate, containing all fields removed or modified from the initial TBSCertificate, above. This authenticates the removed fields to a relying party that only trusts the alternate CA.

   3. The alternate CA signs its TBSCertificate to issue an alternate certificate. This TBSCertificate MUST satisfy the policies of the alternate CA.

   4. The alternate CA extracts the alternate certificate's issuer-specific fields and signature. It returns these to the outer CA as an AlternateIssuerInfo. This contains enough information for the relying party to reconstruct the alternate certificate.

3. If the outer CA participates in CT, run the following steps. These steps MAY run in parallel with step 2. If the outer CA does not participate in CT, skip these steps.

   {:type="a"}
   1. The outer CA signs a precertificate for its initial TBSCertificate, including the critical poison extension, as described in {{Section 3.1 of !RFC6962}}.

   2. The outer CA then requests Signed Certificate Timestamps (SCTs) from CT logs.

4. The outer CA appends an `id-ce-embeddedSCT-CTv1` (OID 1.3.6.1.4.1.11129.2.4.2) extension to its initial TBSCertificate. The extension contains the AlternateIssuerInfo and, if applicable, SCTs collected above.

5. The outer CA signs its final TBSCertificate to issue the outer certificate. This TBSCertificate MUST satisfy the policies of the outer CA.

{{fig-turducken-issuance}} illustrates this process. Although the two issuance processes are now integrated, from the outer CA's perspective, it is analogous to embedding SCTs in CT. From the alternate CA's perspective, this is issuing a certificate with a specific extension added.

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

                                 Alternate Certificate
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
|  +--------------+   |   <-----   +--------------+
|  |    B SIG     |   |            |    B SIG     |
+--+--------------+---+            +--------------+
~~~
{: #fig-turducken-issuance title="A diagram of how the alternate and outer certificates are issued. A is the outer CA, and B is an alternate CA."}

While these are two distinct CAs, their policies and certificate issuance have to be sufficiently aligned to issue these closely related certificates. Often the two CAs will be operated by the same entity.

{{certification-authorities}} discusses certificate issuance in more detail.

## Verifying Certificates

When the certificate subject presents the outer certificate to a relying party, relying parties will attempt to validate one of several certificates:

* Relying parties that are not aware of this protocol will ignore the unrecognized SCT type of `alternate_issuer_info` and validate the outer certificate as usual. {{legacy-relying-parties}} discusses this further.

* Upgraded relying parties will reconstruct the alternate certificates and use them as candidate target certificates when building certification paths {{?RFC4158}}. If a relying party finds some valid certification path from some target certificate, outer or alternate, it proceeds with that certification path. This specification does not impose a preference for whether outer or alternate is used in a case where both have a valid certification path.

This allows the same certificate to serve both older relying parties that expect the outer CA, and newer relying parties that expect one of the alternate CAs.

{{relying-parties}} discusses this in more detail.

# Certification Authorities

## Certificate Constraints

Although outer and alternate certificates are conceptually separate, with relying parties accepting one or the other, they are constrained to both share subject information and incorporate parts of each other. Alternate certificates are incorporated into the outer certificate to transmit them. The outer certificate is also partially incorporated into the alternate certificate to mitigate a class of security risks in relying parties. These are described in more detail in {{certificate-mismatch}}.

This means outer and alternate CAs are expected to coordinate their certificate profiles and issuance processes, as outlined in {{issuing-certificates}}. Concretely, the certificates are constrained as follows:

The outer and alternate certificates MUST have a `version` of v3 and MUST omit `issuerUniqueID` and `subjectUniqueID`. These are preexisting requirements from {{Sections 4.1.2.1 and 4.1.2.8 of !RFC5280}}.

The outer and alternate certificates MUST have the same `validity`, `subject`, and `subjectPublicKeyInfo` values.

The outer and alternate certificates' `extensions` lists MUST each consist of, in order, zero or more *common extensions*, zero or more *issuer-specific extensions*, and a single *final extension*. These MUST satisfy the following:

* The common extensions across all certificates MUST be equal and appear in the same order.

* The issuer-specific extensions MUST NOT contain any of the following extensions:

  * `id-ce-subjectKeyIdentifier`, {{Section 4.2.1.2 of !RFC5280}}
  * `id-ce-keyUsage`, {{Section 4.2.1.3 of !RFC5280}}
  * `id-ce-subjectAltName`, {{Section 4.2.1.6 of !RFC5280}}
  * `id-ce-subjectDirectoryAttributes`, {{Section 4.2.1.8 of !RFC5280}}
  * `id-ce-basicConstraints`, {{Section 4.2.1.9 of !RFC5280}}
  * `id-ce-nameConstraints`, {{Section 4.2.1.10 of !RFC5280}}
  * `id-ce-extKeyUsage`, {{Section 4.2.1.12 of !RFC5280}}
  * `id-pe-subjectInfoAccess`, {{Section 4.2.2.2 of !RFC5280}}
  * `id-CABFOrganizationIdentifier`, {{CABF-EV}}

* PKI deployments MAY impose additional restrictions on issuer-specific extensions by policy. In particular, deployments SHOULD forbid extensions which would change the certificate's subject information in ways which would risk the issues described in {{certificate-mismatch}}. The following is a non-exhaustive list of extensions which would be safe to permit as issuer-specific in most applications:

  * `id-ce-authorityKeyIdentifier`, {{Section 4.2.1.1 of ?RFC5280}}
  * `id-ce-certificatePolicies`, {{Section 4.2.1.4 of ?RFC5280}}
  * `id-ce-issuerAltName`, {{Section 4.2.1.7 of ?RFC5280}}
  * `id-ce-cRLDistributionPoints`, {{Section 4.2.1.13 of ?RFC5280}}
  * `id-ce-freshestCRL`, {{Section 4.2.1.15 of ?RFC5280}}
  * `id-pe-authorityInfoAccess`, {{Section 4.2.2.1 of ?RFC5280}}
  * `id-pe-qcStatements`, {{Section 3.2.6 of ?RFC3739}}

* The outer certificate's final extension MUST have type `id-ce-embeddedSCT-CTv1`, with contents as described in {{alternate-certificate-information}}. This embeds each alternate certificate in the outer certificate.

* Each alternate certificate's final extension MUST have type `id-pe-outerCertificateBinding`, with contents as described in {{outer-certificate-binding}}. This authenticates most of the outer certificate from the alternate certificate.

## Alternate Certificate Information

Each alternate certificate is described as differences from the outer certificate in an AlternateIssuerInfo structure. An AlternateIssuerInfo is defined as follows:

~~~ asn.1
AlternateIssuerInfo ::= SEQUENCE {
    serialNumber         CertificateSerialNumber,
    signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                             {SignatureAlgorithms}},
    issuer               Name,
    commonExtensionCount INTEGER (0..MAX),
    issuerExtensions     SEQUENCE OF Extension{{CertExtensions}},
    signatureValue       BIT STRING
}
~~~

An AlternateIssuerInfo's fields are defined as follows:

* `serialNumber` is the alternate certificate's serial number.
* `signatureAlgorithm` is the alternate certificate's signature algorithm. This value appears in both the TBSCertificate and Certificate structures.
* `issuer` is the alternate certificate's issuer name.
* `commonExtensionCount` is the number of common extensions, as defined in {{certificate-constraints}}. This value MUST be strictly less than the number of extensions in the outer certificate, to exclude the outer certificate's final extension.
* `issuerExtensions` is the alternate certificate's issuer-specific extensions, as defined in {{certificate-constraints}}.
* `signatureValue` is the alternate certificate's signature value. This is a signature over the reconstructed TBSCertificate, not the AlternateIssuerInfo.

### Signed Certificate Timestamp Encoding

The AlternateIssuerInfos for each alternate certificate are embedded in the outer certificate. Instead of a custom extension, this document embeds each AlternateIssuerInfo as a new type of SCT in the outer certificate's `id-ce-embeddedSCT-CTv1` (OID 1.3.6.1.4.1.11129.2.4.2) extension. This extension MUST be the final extension in the outer certificate. {{certificate-transparency-log-sizes}} discusses the motivation for embedding the alternate certificates as SCTs.

The contents of this extension are defined in {{Section 3.3 of !RFC6962}}, but the definition is replicated here for clarity. The `extnValue` OCTET STRING field itself contains a DER-encoded OCTET STRING. This OCTET STRING's contents are SignedCertificateTimestampList defined using the TLS presentation language below. Note there are two layers of OCTET STRING encoding.

~~~ tls-presentation
opaque SerializedSCT<1..2^16-1>;

struct {
    SerializedSCT sct_list<1..2^16-1>;
} SignedCertificateTimestampList;
~~~

Each AlternateIssuerInfo is formated as a TransItem structure ({{Section 4.5 of !RFC9162}}) with a `versioned_type` of `alternate_issuer_info`, defined below:

~~~ tls-presentation
enum {
    alternate_issuer_info(TBD3), (0xFFFF)
} VersionedTransType;

struct {
    VersionedTransType versioned_type;
    select (versioned_type) {
        case alternate_issuer_info:
            opaque contents<1..2^16-1>;
    } data;
} TransItem;
~~~

The `contents` field contains the DER encoding of the AlternateIssuerInfo.

The serialized TransItem is then placed in the SignedCertificateTimestampList as an opaque SerializedSCT. The SignedCertificateTimestampList MAY contain other SCT constructions, notably the SignedCertificateTimestamp structure defined in {{Section 3.2 of !RFC6962}} if the outer CA participates in CT. Per {{legacy-relying-parties}}, relying parties are expected to ignore unrecognized SCT versions.

Note: {{?RFC6962}} was obsoleted by {{?RFC9162}}, but the two protocols use separate extensions. AlternateIssuerInfos are embedded in the extension from {{?RFC6962}} for compatibility with existing deployments. They extend the structure from {{?RFC9162}} to make use of the registry defined in {{Section 10.2.3 of ?RFC9162}}. This can be embedded in the extension from {{?RFC6962}} because the two-byte VersionedTransType type reserves 0x0000..0x00FF to avoid overlapping with SignedCertificateTimestamp's one-byte `v1(0)` version value. Allocating new values from VersionedTransType preserves this separation.

## Outer Certificate Binding

Each alternate certificate contains an outer certificate binding extension, defined below:

~~~ asn.1
OuterCertificateBinding ::= SEQUENCE {
    serialNumber         CertificateSerialNumber,
    signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                            {SignatureAlgorithms}},
    issuer               Name,
    commonExtensionCount INTEGER (0..MAX),
    issuerExtensions     SEQUENCE OF Extension{{CertExtensions}}
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

The OuterCertificateBinding structure is similar to the AlternateIssuerInfo, except that it does not contain a `signatureValue` field. It describes the outer certificate, relative to the alternate certificate.

* `serialNumber` is the outer certificate's serial number.
* `signatureAlgorithm` is the outer certificate's signature algorithm. This value appears in both the TBSCertificate and Certificate structures.
* `issuer` is the outer certificate's issuer name.
* `commonExtensionCount` is the number of common extensions, as defined in {{certificate-constraints}}. This value MUST be strictly less than the number of extensions in the alternate certificate, to exclude the outer certificate binding extension itself.
* `issuerExtensions` is the outer certificate's issuer-specific extensions, as defined in {{certificate-constraints}}.

The outer certificate binding extension MUST be the final extension in the alternate certificate and MUST be non-critical. It contains enough information to reconstruct the outer CA's initial TBSCertificate (see {{issuing-certificates}}). CAs MUST NOT issue an outer certificate binding extension if this reconstructed TBSCertificate violates the constraints in {{certificate-constraints}}, or is otherwise inconsistent with applicable policies. In particular, the `issuerExtensions` field MUST NOT contain any issuer-specific extensions forbidden by {{certificate-constraints}} or applicable policies.

This binding mitigates the security risks described in {{certificate-mismatch}} by authenticating most of the replaced outer certificate by the alternate CA.

Note that the design of this mechanism precludes nested alternate certificates since both the outer certificate's `id-ce-embeddedSCT-CTv1` extension, and the alternate certificate's `id-pe-outerCertificateBinding` extension must be last, thereby precluding a certificate from simultaneously being both an outer and alternate certificate. This does not preclude the alternate certificate from embedding SCTs because {{?RFC6962}} does not have an ordering requirement.

# Relying Parties

Relying parties process alternate certificates as an extension of X.509 path building {{?RFC4158}}.

While collecting candidate certification paths, a relying party checks if the outer certificate's final extension is `id-ce-embeddedSCT-CTv1`. If so, it looks for SCTs formatted as in {{signed-certificate-timestamp-encoding}}. For each such SCT, it decodes the AlternateIssuerInfo structure. For each successfully-decoded AlternateIssuerInfo, the relying party then reconstructs the alternate certificate as described in {{reconstructing-the-alternate-certificate}}.

If successful, the alternate certificate is used as an alternate target certificate. The relying party then considers certification paths that end at the alternate certificate. If certification path validation ({{Section 6 of !RFC5280}}) succeeds for some path, the relying party proceeds with this path, as if it had found a valid path ending at the outer certificate.

Certification paths for outer and alternate certificates are processed independently. Relying parties MAY extract and consider alternate certificates regardless of the trust, revocation, or expiry status of the outer certificate.

An outer certificate with many AlternateIssuerInfo structures can require more processing time in the relying party. This is similar to path building itself {{?RFC4158}}, X.509 policy validation {{?RFC9618}}, certification path length, and other factors that contribute to X.509 scaling. Relying parties SHOULD limit the number of alternate certificates in a single outer certificate they will process. For example, if the relying party has a path building iteration limit, considering an alternate certificate can contribute to that limit. An attacker can inject arbitrarily many AlternateIssuerInfo structures into an unverified outer certificate, so this avoids a denial of service vector.

## Reconstructing the Alternate Certificate

The following procedure reconstructs an alternate certificate from the outer certificate and an AlternateIssuerInfo.

1. Check each of the following. If any check fails, abort this procedure.

   * The outer certificate's `version` is `v3`.
   * The outer certificate's `signatureAlgorithm` and its TBSCertificate's `signature` fields are equal.
   * The outer certificate has no `subjectUniqueID` or `issuerUniqueID` field.
   * The outer certificate has at least `commonExtensionCount + 1` extensions and the final extension is `id-ce-embeddedSCT-CTv1`.

2. Make a copy of the outer certificate as a Certificate structure.

3. Replace the TBSCertificate's `serialNumber` field with the AlternateIssuerInfo's `serialNumber`. Let `outerSerialNumber` be the replaced value.

4. Replace the Certificate's `signatureAlgorithm` field and the TBSCertificate's `signature` field with the AlternateIssuerInfo's `signatureAlgorithm`. Let `outerSignatureAlgorithm` be the replaced value.

5. Replace the TBSCertificate's `issuer` field with the AlternateIssuerInfo's `issuer`. Let `outerIssuer` be the replaced value.

6. Remove the TBSCertificate's final extension. The processing steps in {{relying-parties}} ensure this extension has type `id-ce-embeddedSCT-CTv1` and contains the AlternateIssuerInfo, formatted as described in {{signed-certificate-timestamp-encoding}}.

7. Remove all but the first `commonExtensionCount` extensions in the TBSCertificate. Let `outerIssuerExtensions` be the removed extensions.

8. Check `outerIssuerExtensions` and the AlternateIssuerInfo's `issuerExtensions` as described in {{checking-issuer-specific-extensions}}. If rejected, abort this procedure.

9. Append the AlternateIssuerInfo's `issuerExtensions` to the TBSCertificate.

10. Append a non-critical outer certificate binding extension ({{outer-certificate-binding}}) to the TBSCertificate such that:

    * `serialNumber` is `outerSerialNumber`.
    * `signatureAlgorithm` is `outerSignatureAlgorithm`.
    * `issuer` is `outerIssuer`.
    * `commonExtensionCount` is the AlternateIssuerInfo's `commonExtensionCount` value.
    * `issuerExtensions` is `outerIssuerExtensions`.

11. Replace the Certificate's `signatureValue` field with the AlternateIssuerInfo's `signatureValue`.

## Checking Issuer-Specific Extensions

{{certificate-constraints}} aims to forbid `outerIssuerExtensions` and `issuerExtensions` above from containing any extensions that would change the certificate's subject information. However, X.509 is extensible, so a relying party cannot enforce this restriction in full. In particular, relying parties MUST accept unrecognized issuer-specific extensions in this procedure. (If the unrecognized issuer-specific extension is critical, it will likely be rejected later during path validation.)

The relying party SHOULD check for and reject the forbidden issuer-specific extensions listed in {{certificate-constraints}} and other issuer-specific extensions known to be forbidden by local policy. The relying party MAY skip this check for any extension that its path verifier does not recognize. It also MAY skip this check if all subsequent access checks reliably inspect the correct certificate, as described in {{certificate-mismatch}}.

## Input Certificates and Validated Certificates

For this section, we define the input certificate to be the entire certificate being processed (typically the outer certificate), and the validated certificate to be the one for which the certification path was checked, which may be the outer certificate or an alternate certificate.
Note that the input certificate will always contain the validated target certificate, but does not specify which one it is.
This section considers potential impacts of the input certificate and the validated certificate being different.

In contexts that are defined based on the certificate that was sent over the wire, the input certificate is used. For example:

* The TLS transcript hash ({{Section 4.1 of ?RFC9846}}) is computed from the Certificate message and thus the bytes of the input certificate.
* The tls-server-end-point channel binding ({{Section 4 of ?RFC5929}}) is computed from the bytes of the input certificate.

In contexts that are defined based on the certificate that was validated, notably access control checks, the validated certificate SHOULD be used. {{certificate-mismatch}} discusses this case in more detail.

This distinction is a generalization of an existing distinction in path-building X.509 applications. The input list of certificates may differ from the final certification path that was built. Applications are already expected to separate these cases, but they were not previously required to consider different target certificates.

# Deployment Considerations

## Legacy Services

This document defines a temporary transitionary mechanism for deployments where some legacy services do not support multiple certificates. Services that support multiple certificates directly SHOULD NOT use this mechanism. Deployments are RECOMMENDED to enforce this in CAs and relying parties.

For example, in a post-quantum transition for TLS, this mechanism is only applicable to unmodified legacy services that only have traditional end-entity keys. Once a service has a post-quantum end-entity key, it can be assumed to be relatively up-to-date and necessarily maintains separate end-entity keys for both legacy and post-quantum relying parties. The service also necessarily has sufficient certificate selection capabilities ({{Section 4.5.1.2 of ?RFC9846}}) to select between its supported relying parties. Such a service would have no need for this document. Accordingly, in a TLS deployment using this mechanism for a post-quantum transition:

* CAs SHOULD NOT embed alternate certificates if the end-entity key is post-quantum.
* Relying parties SHOULD ignore alternate certificates if the end-entity key is post-quantum.

This ensures that, when the post-quantum transition is completed, services will no longer rely on this mechanism and implementations can remove the supporting logic.

A given deployment SHOULD only deploy this mechanism once, for only one transition. After that transition has completed, the deployment SHOULD have transitioned to a state where certificate holders support multiple certificates.

## Legacy Relying Parties

The primary backwards compatibility goal of this specification is that a relying party that is unaware of this specification will process the outer certificate as if the alternate was not present. This assumes that existing certificate parsers will ignore unrecognized SCTs of type `alternate_issuer_info` and continue processing the rest of the certificate as usual.

This is believed to be the behavior of all existing parsers, and is supported by both {{?RFC6962}} and {{?RFC9162}}:

{{Section 3.3 of ?RFC6962}} says:

> This encoding ensures that TLS clients can
> decode each SCT individually (i.e., if there is a version upgrade,
> out-of-date clients can still parse old SCTs while skipping over new SCTs whose versions they don't understand).

{{Section 6.3 of ?RFC9162}} says:

> This encoding ensures that TLS clients can decode each TransItem individually (so, for example, if there is a version upgrade, out-of-date clients can still parse old TransItem structures while skipping over new TransItem structures whose versions they don't understand).

## Certificate Transparency Log Sizes

In deployments that use CT {{?RFC6962}}, a direct post-quantum transition risks significantly increasing the sizes of CT logs. {{IETF124-PLANTS}} estimated an 8.3x size increase from migrating to ML-DSA-44.

Merkle Tree Certificates {{?I-D.ietf-plants-merkle-tree-certs}} provide a quantum-resistant transparency construction that avoids this size increase. However, when post-quantum Merkle Tree Certificates are embedded as alternate certificates, the resulting large AlternateIssuerInfo structures will instead be logged with the outer certificate. The traditional CT logs would increase in size during the transition to Merkle Tree Certificates.

{{signed-certificate-timestamp-encoding}} partially mitigates this new increase by embedding AlternateIssuerInfo structures in SCTs. When the outer certificate's precertificate is logged, the precertificate will omit these SCTs and thus the added structures.

This is only a partial mitigation because the AlternateIssuerInfo will still be logged when the final certificate with embedded SCTs is logged. Deployments using this document to transition away from a CT-based PKI thus SHOULD permit CT logs to reject logging of any certificates with embedded SCTs of type `alternate_issuer_info`. This will not impact other embedded SCTs, which refer to logged precertificates rather than logged final certificates.

# Security Considerations

## Separate Certificates

Although each alternate certificate is ultimately encoded relative to the outer certificate, the alternate CA's signature is on the reconstructed alternate TBSCertificate, so it is still considered to have separately issued the reconstructed alternate certificate. In particular:

* The alternate TBSCertificate MUST satisfy the policies of the alternate CA, including any domain validation. Misissuance of an alternate certificate remains misissuance.

* Revocation of each certificate is independent. Revoking the outer certificate does not revoke the alternate certificates and vice versa.

When relying parties evaluate candidate certification paths, they likewise treat each possible target certificate separately. If the relying party accepts an alternate certificate, it does not verify the outer certificate or even necessarily trust the outer CA. In particular, in the post-quantum transition, the outer CA is a traditional CA, so its key could be compromised by a CRQC.

## Certificate Mismatch

Access checks in the relying party SHOULD act on the certification path that was ultimately validated, failing to do so can result in access control bypass vulnerabilities. In support of this, APIs that return the validated certification path SHOULD reflect the correct target certificate.

However, this breaks an application invariant. Previously, the target certificate would never change as a result of path building. Which trust anchor it chains to and via which path might change, but the end entity certificate would not. An existing application might assume this invariant and inspect the original target certificate for some access check. If the application's X.509 implementation is updated independently from the rest of the application, it may inadvertently use the wrong certificate, which could carry security implications if the content of the alternate and outer certificate differ. In some cases, the X.509 implementation's APIs might not even return the validated path, only a success or failure status.

X.509 implementations MAY further mitigate the risk by limiting alternate certificate support to applications that opt in. However, this might undesirably slow down PKI transitions that depend on alternate certificates. Additionally, a large application might opt in, yet forget to update some component.

This document further mitigates this risk in two ways:

1. Where possible, limiting alternate certificates to encoding the same subject information as the outer certificate.
2. Requiring the alternate CA to sign over removed or replaced outer certificate fields, via the outer certificate binding extension.

This contrasts with {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}}, which allow the second certificate to differ significantly. There, the application is expected to be fully aware of the second certificate.

If a more general protocol were instead used in this document, path validation might, for example, authenticate an alternate certificate's public key, while the rest of the application acts on a different, unverified public key in the outer certificate. This could allow an attacker to bypass certificate-based authentication. However, alternate certificates cannot replace the `subjectPublicKeyInfo` field in this document, so a public key mismatch is not possible.

X.509 extensions complicate this mitigation. X.509 does not structurally distinguish between subject and issuer extensions, in a way that would allow a relying party to classify unrecognized extension types. If the relying party rejects unknown issuer-specific extensions, it is not possible to define new such extensions. However, if it accepts unknown extensions, it could allow an extension that downstream components depend on being the same between the alternate and outer certificate.

Instead, the outer certificate binding extension mitigates this risk more generally. Except for `id-ce-embeddedSCT-CTv1`, extensions replaced or removed from the outer certificate are still signed by the alternate CA. This prevents an arbitrary attacker from manipulating those fields. {{outer-certificate-binding}} additionally holds the alternate CA responsible for meeting the requirements in {{certificate-constraints}} and other deployment-specific policies, to forbid the alternate CA itself from enabling an attack. CAs are expected to not sign unknown extensions, so this does not conflict with extensibility.

Ultimately, the alternate CA is responsible for ensuring that any extensions removed or modified will not cause interoperability or security problems among the target relying party base.

However, there are some cases where this is complicated by relying-party-imposed constraints on the CA. If the alternate CA were under, say, a name constraint ({{Section 4.2.1.10 of !RFC5280}}), the relying party could not rely on the alternate CA alone to mitigate subjectAltName mismatches. If the alternate certificate contained a permitted subjectAltName, while the outer certificate contained an excluded one, a mismatch could bypass the name constraint. {{checking-issuer-specific-extensions}} recommends that the relying party check replaced extensions in a more limited way. Though the relying party might not recognize all extensions, its path validator necessarily recognizes all extensions that it incorporates into path validation.

# IANA Considerations

## PKIX Module Identifier

IANA is requested to add the following entry in the "SMI Security for PKIX Module Identifier" registry {{?RFC7299}}:

| Decimal | Description                          | References |
|---------|--------------------------------------|------------|
| TBD1    | id-mod-embeddedAlternateIssuers-2026 | [this-RFC] |

## PKIX Certificate Extension

IANA is requested to add the following entry in the "SMI Security for PKIX Certificate Extension" registry {{?RFC7299}}:

| Decimal | Description                   | References |
|---------|-------------------------------|------------|
| TBD2    | id-pe-outerCertificateBinding | [this-RFC] |

## Versioned Transparency Item Types

IANA is requested to add the following entry in the "VersionedTransTypes" registry {{?RFC9162}}:

| Value | Type and Version      | Reference  |
|-------|-----------------------|------------|
| TBD3  | alternate_issuer_info | [this-RFC] |

--- back

# ASN.1 Module

This module uses structures defined in {{!RFC5912}}.

~~~ asn.1
EmbeddedAlternateIssuers-2026
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-mod(0)
    id-mod-embeddedAlternateIssuers-2026(TBD1) }

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
  CertExtensions
  FROM PKIX1Implicit-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkix1-implicit-02(59) }
  Name, CertificateSerialNumber, SignatureAlgorithms
  FROM PKIX1Explicit-2009 -- in [RFC5912]
    { iso(1) identified-organization(3) dod(6) internet(1)
      security(5) mechanisms(5) pkix(7) id-mod(0)
      id-mod-pkix1-explicit-02(51) }
;

AlternateIssuerInfo ::= SEQUENCE {
    serialNumber         CertificateSerialNumber,
    signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                             {SignatureAlgorithms}},
    issuer               Name,
    commonExtensionCount INTEGER (0..MAX),
    issuerExtensions     SEQUENCE OF Extension{{CertExtensions}},
    signatureValue       BIT STRING
}

OuterCertificateBinding ::= SEQUENCE {
    serialNumber         CertificateSerialNumber,
    signatureAlgorithm   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                            {SignatureAlgorithms}},
    issuer               Name,
    commonExtensionCount INTEGER (0..MAX),
    issuerExtensions     SEQUENCE OF Extension{{CertExtensions}}
}

id-pe-outerCertificateBinding OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) pe(1) TBD2 }

ext-outerCertificateBinding EXTENSION ::= {
    SYNTAX OuterCertificateBinding
    IDENTIFIED BY id-pe-outerCertificateBinding
    CRITICALITY {FALSE}
}

END
~~~

# Acknowledgments
{:numbered="false"}

Thanks to the authors of {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}} for exploring the space of how to represent related certificates. While this document is intentionally more specialized, it has benefited significantly from their work.

Thanks also to Bob Beck for reviewing the document and providing feedback.
