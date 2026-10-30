---
title: "Embedded Alternate Issuers"
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

This document defines a mechanism to embed one or more alternate certificates within a single outer certificate. The outer certificate remains parseable to a legacy relying party that is unaware of this specification. Each alternate certificate certifies the same subject information, but with a different issuer. Rather than a general purpose mechanism, embedded alternate certificates are a temporary measure for PKI transitions, such as the post-quantum transition, in PKIs with significant legacy deployments.

--- middle

# Introduction

In transitioning a Public Key Infrastructure (PKI) to post-quantum cryptography, it is necessary to reconfigure relying parties to reject legacy trust anchors. Otherwise, post-quantum certificates do not prevent downgrade attacks. Even if some service has deployed a post-quantum certificate, a cryptographically relevant quantum computer (CRQC) can simply break the key of some unrelated traditional certification authority (CA) and forge a certificate for that service. The service's choice of CA does not impact this attack, only the relying party's trust anchors.

Some applications, such as the Web, have constraints that make this particularly challenging:

* Relying parties must continue to connect to legacy services that do not yet support post-quantum algorithms. Waiting for services to universally become post-quantum-capable will take time.

* Relying parties support enough services that pre-configuring different trust anchors for different services is impractical.

* Legacy services must themselves continue to support legacy relying parties that do not support post-quantum algorithms or trust anchors.

* In addition to lacking post-quantum algorithms, some legacy services are also unable to configure and select between multiple certificates.

{{PQ-AUTH-ROADMAP}} and {{IETF126-PQ-AUTH}} discuss how, for these applications, it is sufficient to migrate to a state where:

1. Legacy services serve certificates with post-quantum issuers, even if the end-entity keys are still traditional. This is known as a *post-quantum opt-out certificate*. It provides a quantum-resistant proof to the relying party that the service is not yet post-quantum-capable.

2. Relying parties only accept post-quantum issuers, but accept both post-quantum and traditional end-entity keys.

This issuer-side transition protects post-quantum services from downgrade, while remaining compatible with legacy services. However, the final two constraints prevent one from simply replacing every legacy service's certificate on renewal, because the legacy services will lose compatibility with legacy relying parties.

This document solves this by providing a mechanism to embed the post-quantum opt-out certificate into a legacy certificate. This meets the security goals of delivering the post-quantum opt-out signal to updated relying parties, while still presenting a compatible certificate to unmodified legacy relying parties. The embedding construction is also designed to meet two other requirements:

* It avoids increasing the size of logged precertificates in Certificate Transparency (CT), as described in {{certificate-transparency-log-sizes}}.
* It aims to mitigate security risks if some components consume alternate certificates without awareness from other components, as described in {{certificate-mismatch}}.

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

Outer CA:
: The CA that issues the outer certificate.

Alternate certificate:
: One of the certificates embedded in the outer certificate. An alternate certificate certifies the same subject information as the outer certificate, but via a different issuer.

Alternate CA:
: A CA that issues one of the alternate certificates.

Post-quantum opt-out certificate:
: An end-entity certificate with a traditional subject key and post-quantum issuer. It can be embedded as an alternate certificate in a fully traditional outer certificate.

# Overview

Outer and alternate certificates are closely related and issued in an integrated process:

* All certificates contain the same subject information, including subjectPublicKeyInfo and subjectAltNames, but they differ in signature and issuer-specific information. The common subject-specific extensions all share an ordering.

* The outer certificate embeds an AlternateIssuerInfo for each alternate certificate. This contains both the signature and issuer-specific information for the alternate certificate. It is sufficient to reconstruct the alternate certificate.

* Each alternate certificate contains an outer certificate binding extension. This contains the issuer-specific fields of the outer certificate, but not the signature. This authenticates the outer certificate's issuer-specific information in relying parties that only trust the alternate CA.

## Issuing Certificates

After subject information is validated according to the policies of each CA involved, the certificates are issued in the following process:

1. The outer CA constructs an initial TBSCertificate with the validated subject information and issuer fields reflecting the outer CA. It sets `notBefore` and `notAfter` such that the certificate validity would be compatible with each alternate CA.

2. For each alternate CA, run the following steps. The steps for each alternate CA MAY run in parallel.

   {:type="a"}
   1. The alternate CA constructs a TBSCertificate based on the outer CA's initial TBSCertificate. The outer CA's issuer-specific fields are removed and replaced with ones reflecting the alternate CA.

   2. The alternate CA appends an outer certificate binding extension to its TBSCertificate, containing all fields removed from the initial TBSCertificate, above. This authenticates the removed fields to a relying party that only trusts the alternate CA.

   3. The alternate CA signs its TBSCertificate to issue an alternate certificate. This TBSCertificate MUST satisfy the policies of the alternate CA.

   4. The alternate CA extracts the alternate certificate's issuer-specific fields and signature. It returns these to the outer CA as an AlternateIssuerInfo. This contains enough information for the relying party to reconstruct the alternate certificate.

3. If the outer CA participates in CT, it additionally signs a precertificate for its initial TBSCertificate, including the critical poison extension, as described in {{Section 3.1 of !RFC6962}}. The outer CA then requests Signed Certificate Timestamps (SCTs) from CT logs. This step MAY run in parallel with step 2.

4. The outer CA collects all AlternateIssuerInfos and SCTs and appends an `id-ce-embeddedSCT-CTv1` extension to its initial TBSCertificate.

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
+  +--------------+   |   <-----   +--------------+
|  |    B SIG     |   |            |    B SIG     |
+--+--------------+---+            +--------------+
~~~
{: #fig-turducken-issuance title="A diagram of how the alternate and outer certificates are issued. A is the outer CA, and B is an alternate CA."}

{{certification-authorities}} discusses this in more detail.

## Verifying Certificates

When the certificate subject presents the outer certificate to a relying party, relying parties will attempt to validate one of several certificates:

* Older relying parties that are not aware of this protocol will ignore the unrecognized SCT and validate the outer certificate as usual.

* Newer relying parties will reconstruct the alternate certificates and use them as candidate target certificates when building certification paths {{!RFC4158}}. If it finds some valid certification path from some target certificate, outer or alternate, it proceeds with that certification path.

This allows the same certificate to serve both older relying parties that expect the outer CA, and newer relying parties that expect one of the alternate CAs.

{{relying-parties}} discusses this in more detail.

# Certification Authorities

## Certificate Constraints

Although outer and alternate certificates are conceptually separate, with relying parties accepting one or the other, they are constrained to both share subject information and incorporates parts of each other. Alternate certificates are incorporated into the outer certificate to transmit them. The outer certificate is also partially incorporated into the alternate certificate to mitigate a class of security risks in relying parties. These are described in more detail in {{certificate-mismatch}}.

This means outer and alternate CAs are expected to coordinate their certificate profiles and issuance processes, as outlined in {{issuing-certificates}}. Concretely, the certificates are constrained as follows:

The outer and alternate certificates MUST have a `version` of v3 and MUST omit `issuerUniqueID` and `subjectUniqueID`. These are preexisting requirements from {{Sections 4.1.2.1 and 4.1.2.8 of !RFC5280}}.

The outer and alternate certificates MUST have the same `validity`, `subject`, and `subjectPublicKeyInfo` values.

The outer and alternate certificates' `extensions` lists MUST be dividable into, in order, some number of *common extensions*, some number of *issuer-specific extensions*, and a single *final extension*. These MUST satisfy the following:

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

* PKI deployments MAY impose additional restrictions on issuer-specific extensions by policy. In particular, deployments SHOULD forbid extensions which would change the certificate's subject information in ways which would risk issues the described in {{certificate-mismatch}}. The following is a non-exhaustive list of extensions which would be safe to permit as issuer-specific in most applications:

  * `id-ce-authorityKeyIdentifier`, {{Section 4.2.1.1 of !RFC5280}}
  * `id-ce-certificatePolicies`, {{Section 4.2.1.4 of !RFC5280}}
  * `id-ce-issuerAltName`, {{Section 4.2.1.7 of !RFC5280}}
  * `id-ce-cRLDistributionPoints`, {{Section 4.2.1.13 of !RFC5280}}
  * `id-ce-freshestCRL`, {{Section 4.2.1.15 of !RFC5280}}
  * `id-pe-authorityInfoAccess`, {{Section 4.2.2.1 of !RFC5280}}
  * `id-pe-qcStatements`, {{Section 3.2.6 of !RFC3739}}

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

AlternateIssuerInfoList ::= SEQUENCE OF AlternateIssuerInfo
~~~

An AlternateIssuerInfo's fields are defined as follows:

* `serialNumber` is the alternate certificate's serial number.
* `signatureAlgorithm` is the alternate certificate's signature algorithm. This value appears in both the TBSCertificate and Certificate structures.
* `issuer` is the alternate certificate's issuer name.
* `commonExtensionCount` is the number of common extensions, as defined in {{certificate-constraints}}. This value MUST be strictly less than the number of extensions in the outer certificate, to exclude the outer certificate's final extension.
* `issuerExtensions` is the alternate certificate's issuer-specific extensions, as defined in {{certificate-constraints}}.
* `signatureValue` is the alternate certificate's signature value. This is a signature over the reconstructed TBSCertificate, not the AlternateIssuerInfo.

### Signed Certificate Timestamp Encoding

The AlternateIssuerInfos for each alternate certificate are collected in an AlternateIssuerInfoList, which is embedded in the outer certificate. Instead of a custom extension, this document embeds them as a SignedCertificateTimestamp (SCT) in the outer certificate's `id-ce-embeddedSCT-CTv1` (OID 1.3.6.1.4.1.11129.2.4.2) extension, as defined in {{Section 3.3 of !RFC6962}}. This extension MUST be the final extension in the outer certificate. {{certificate-transparency-log-sizes}} discusses the motivation for embedding in an SCT.

Note: {{!RFC6962}} was obsoleted by {{?RFC9162}}, but the two protocols are incompatible. This document uses some definitions from {{!RFC6962}} for compatibility with existing deployments.

The SCT is formatted as a TransItem ({{Section 4.5 of !RFC9162}}) with a `versioned_type` of `embedded_alternate_issuers`, defined below:

~~~ tls-presentation
enum {
    embedded_alternate_issuers(TBD3), (0xFFFF)
} VersionedTransType;

struct {
    VersionedTransType versioned_type;
    select (versioned_type) {
        case embedded_alternate_issuers:
            opaque alternate_issuer_infos<1..2^24-1>;
    } data;
} TransItem;
~~~

The `alternate_issuer_infos` field contains the DER encoding of the AlternateIssuerInfoList.

Note: This structure uses a two-byte version, while the SignedCertificateTimestamp uses a one-byte version. The VersionedTransType type from {{?RFC9162}} reserves 0x0000..0x00FF to avoid overlapping with the `v1(0)` version value from {{?RFC6962}}. The above structure is defined using {{?RFC9162}} to preserve this property and to make use of the registry defined in {{Section 10.2.3 of ?RFC9162}}. The version allocation means it still can and is used in place of a SignedCertificateTimestamp and not the protocols defined in {{?RFC9162}}.

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
* `commonExtensionCount` is the number of common extensions, as defined in {{certificate-constraints}}. This value MUST be strictly less than the number of extensions in the alternate certificate, to exclude outer certificate binding extension itself.
* `issuerExtensions` is the outer certificate's issuer-specific extensions, as defined in {{certificate-constraints}}.

The outer certificate binding extension MUST be the final extension in the alternate certificate. It contains enough information to reconstruct the outer CA's initial TBSCertificate (see {{issuing-certificates}}). CAs MUST NOT issue an outer certificate binding extension if this reconstructed TBSCertificate violates the constraints in {{certificate-constraints}}, or is otherwise inconsistent with applicable policies. In particular, the `issuerExtensions` field MUST NOT contain any issuer-specific extensions forbidden by {{certificate-constraints}} or applicable policies.

This binding mitigates the security risks described in {{certificate-mismatch}} by authenticating most of the replaced outer certificate by alternate CA.

# Relying Parties

When verifying a certificate, a relying party checks if the outer certificate's final extension is `id-ce-embeddedSCT-CTv1`. If so, it looks for an SCT formatted as in {{signed-certificate-timestamp-encoding}}. If found, it decodes the SCT's `signature` value as a DER-encoded AlternateIssuerInfoList structure.

If any AlternateIssuerInfo has a recognized `issuer`, the relying party reconstructs the alternate certificate as described in {{reconstructing-the-alternate-certificate}}. If successful, the alternate certificate is used as a candidate target certificate when building certification paths {{!RFC4158}}.

If certification path validation ({{Section 6 of !RFC5280}}) succeeds for any path ending at an alternate certificate, the relying party accepts the certificate, even if it would otherwise not accept the outer certificate.

An outer certificate with many AlternateIssuerInfo structures can require more processing time in the relying party. This is similar to path building itself {{?RFC4158}}, X.509 policy validation {{?RFC9618}}, certification path length, and other factors that contribute to X.509 scaling. Relying parties SHOULD limit the number of alternate certificates they will consider. For example, if the relying party has a path building iteration limit, considering an alternate certificate can contribute to that limit.

## Reconstructing the Alternate Certificate

The following procedure reconstructs an alternate certificate from the outer certificate and an AlternateIssuerInfo.

1. Check each of the following. If any check fails, abort this procedure.

   * The outer certificate's `version` is `v3`.
   * The outer certificate's `signatureAlgorithm` and `signature` fields are equal.
   * The outer certificate has no `subjectUniqueID` or `issuerUniqueID` field.
   * The outer certificate has at least `commonExtensionCount + 1` extensions and the final extension is `id-ce-embeddedSCT-CTv1`.

2. Make a copy of the outer certificate as a Certificate structure.

3. Replace the TBSCertificate's `serialNumber` field with the AlternateIssuerInfo's `serialNumber`. Let `outerSerialNumber` be the replaced value.

4. Replace the Certificate's `signatureAlgorithm` field and the TBSCertificate's `signature` field with the AlternateIssuerInfo's `signatureAlgorithm`. Let `outerSignatureAlgorithm` be the replaced value.

5. Replace the TBSCertificate's `issuer` field with the AlternateIssuerInfo's `issuer`. Let `outerIssuer` be the replaced value.

6. Remove the TBSCertificate's final extension, which will be `id-ce-embeddedSCT-CTv1`.

7. Remove all but the first `commonExtensionCount` extensions in the TBSCertificate. Let `outerIssuerExtensions` be the removed extensions.

8. Check `outerIssuerExtensions` and the AlternateIssuerInfo's `issuerExtensions` as described in {{checking-issuer-specific-extensions}}. If rejected, above this procedure.

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

# Deployment Considerations

## Legacy Services

Embedded alternate issuers are a temporary transitionary mechanism for deployments where some legacy services do not support multiple certificates. Services that support multiple certificates directly SHOULD NOT use this mechanism. Deployments are RECOMMENDED to enforce this in CAs and relying parties.

For example, in a post-quantum transition for TLS, embedded alternate issuers are only applicable to unmodified legacy services that only have traditional end-entity keys. Once a service has a post-quantum end-entity key, it can be assumed to be relatively up-to-date and necessarily maintains separate end-entity keys for both legacy and post-quantum relying parties. Such a service would have no need for embedded alternate issuers. Accordingly, in a TLS deployment using embedded alternate issuers for a post-quantum transition:

* CAs SHOULD NOT issue embedded alternate issuers if the end-entity key is post-quantum.
* Relying parties SHOULD ignore embedded alternate issuers if the end-entity key is post-quantum.

This ensures that, when the post-quantum transition is completed, there will be no embedded alternate issuers remaining and implementations can remove the supporting logic.

A given deployment SHOULD only deploy embedded alternate issuers once, for only one transition. After that transition has completed, the deployment SHOULD have transitioned to a state where certificate holders support multiple certificates.

## Certificate Transparency Log Sizes

In deployments that use CT {{!RFC6962}}, a direct post-quantum transition risks significantly increasing the sizes of CT logs. ({{!RFC6962}} was obsoleted by {{?RFC9162}}, but the two protocols are incompatible. This document uses the definitions from {{!RFC6962}} for compatibility with existing deployments.) {{IETF124-PLANTS}} estimated an 8.3x size increase from migrating to ML-DSA-44.

Merkle Tree Certificates {{?I-D.ietf-plants-merkle-tree-certs}} provide a quantum-resistant transparency construction that avoids this size increase. However, when Merkle Tree Certificates are combined with embedded alternate issuers, the resulting large AlternateIssuerInfo structures will instead be logged with the outer certificate. The traditional CT logs would increase in size during the transition to Merkle Tree Certificates.

{{signed-certificate-timestamp-encoding}} partially mitigates this new increase by embedding AlternateIssuerInfo structures in an SCT. When the outer certificate's precertificate is logged, the precertificate will omit this SCT and thus the added structures.

This is only a partial mitigation because the AlternateIssuerInfo will still be logged when the final certificate with embedded SCTs is logged. Deployments using embedded alternate issuers to transition away from a CT-based PKI thus SHOULD permit CT logs to reject logging of any certificates with an embedded AlternateIssuerInfoList. This will not impact other embedded SCTs, which refer to logged precertificates rather than logged final certificates.

# Security Considerations

## Validation

Although each alternate certificate is ultimately encoded relative to the outer certificate, the alternate CA's signature is on the reconstructed alternate TBSCertificate, so it is still considered to have issued the reconstructed alternate certificate. The alternate TBSCertificate MUST satisfy the policies of the alternate CA, including any domain validation. Misissuance of an alternate certificate remains misissuance.

## Certificate Mismatch

A relying party that implements this specification will sometimes validate a certification path for an alternate certificate. This presents a security risk of other parts of the system check the original target certificate instead.

Access checks in the relying party SHOULD act on the certification path that was ultimately validated. In support of this, APIs that return the validated certification path SHOULD reflect the correct target certificate.

However, this breaks an application invariant: previously, the target certificate would never change after path building. An existing application might assume this invariant and inspect the original target certificate for some access check. If the application's X.509 implementation is updated independently from the rest of the application, the above measure might fail.

X.509 implementations MAY further mitigate the risk by limiting alternate certificate support to applications that opt in. However, this might undesirably slow down PKI transitions that depend on alternate certificates. Additionally, a large application might opt-in, yet forget to update some component.

This document further mitigates this risk in two ways:

1. Where possible, limiting alternate certificates to encoding the same subject information as the outer certificate.
2. Requiring the alternate CA to sign over removed or replaced outer certificate fields, via the outer certificate binding extension.

This contrasts with {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}}, which allow the second certificate to differ significantly. There, the application is expected to be fully aware of the second certificate.

If a more general protocol were instead used in this document, path validation might, for example, authenticate an alternate certificate's public key, while the rest of the application acts on a different, unchecked public key in the outer certificate. This would allow an attacker to bypass certificate-based authentication. This is not possible here because alternate certificates cannot replace the `subjectPublicKeyInfo` field.

X.509 extensions complicate this mitigation. X.509 does not distinguish between subject and issuer extensions, and a relying party cannot classify unrecognized extension types. If the relying party rejects unknown issuer-specific extensions, it is not possible to define new such extensions. However, if it accepts unknown extensions, it could allow an extension that downstream components depend on.

Instead, the outer certificate binding extension mitigates this risk more generally. Except for `id-ce-embeddedSCT-CTv1`, extensions replaced or removed from the outer certificate are still signed by the alternate CA. This prevents an arbitrary attacker from manipulating those fields. {{outer-certificate-binding}} additionally holds the alternate CA responsible for meeting the requirements in {{certificate-constraints}} and other deployment-specific policies, to prevent the alternate CA themselves from enabling an attack. CAs are expected to not sign unknown extensions, so this does no conflict with extensibility.

However, there are some cases where the relying party constrains the CA. If the alternate CA were under, say, a name constraint ({{Section 4.2.1.10 of !RFC5280}}), the relying party could not rely on the alternate CA alone to mitigate subjectAltName mismatches. If the alternate certificate contained a permitted subjectAltName, while the outer certificate contained an excluded one, a mismatch could bypass the name constraint. {{checking-issuer-specific-extensions}} recommends that the relying party check replaced extensions in a more limited way. Though the relying party might not recognize all extensions, its path validator necessarily recognizes all extensions that it incorporates into path validation.

# IANA Considerations

## PKIX Module Identifier

IANA is requested to add the following entry in the "SMI Security for PKIX Module Identifier" registry {{!RFC7299}}:

| Decimal | Description                          | References |
|---------|--------------------------------------|------------|
| TBD1    | id-mod-embeddedAlternateIssuers-2026 | [this-RFC] |

## PKIX Certificate Extension

IANA is requested to add the following entry in the "SMI Security for PKIX Certificate Extension" registry {{!RFC7299}}:

| Decimal | Description                   | References |
|---------|-------------------------------|------------|
| TBD2    | id-pe-outerCertificateBinding | [this-RFC] |

## Versioned Transparency Item Types

IANA is requested to add the following entry in the "VersionedTransTypes" registry {{!RFC9162}}:

| Value | Type and Version           | Reference  |
|-------|----------------------------|------------|
| TBD3  | embedded_alternate_issuers | [this-RFC] |

--- back

# ASN.1 Module

This module uses structures defined in {{!RFC5912}} and {{!RFC9162}}.

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

AlternateIssuerInfoList ::= SEQUENCE OF AlternateIssuerInfo

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

END
~~~

# Acknowledgments
{:numbered="false"}

Thanks to the authors of {{?I-D.bonnell-lamps-chameleon-certs}} and {{?I-D.ietf-lamps-certdiscovery}} for exploring the space of how to represent related certificates. While this document is intentionally more specialized, it has benefited significantly from their work.

Thanks also to Bob Beck for reviewing the document and providing feedback.
