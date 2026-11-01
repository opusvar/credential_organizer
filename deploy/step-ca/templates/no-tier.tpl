{{- /* OIDC / ACME / SCEP provisioners: self-service, never emits a URI SAN
       (so a CSR cannot smuggle urn:cvc:tier:*). Relying parties treat a cert
       without urn:cvc:tier as having no access. */ -}}
{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}
