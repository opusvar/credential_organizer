{{- /* Device leaf. Identity SANs come ONLY from signed token claims (.Token),
       never from the CSR. Used by the issuer-* JWK provisioners. */ -}}
{{- if not (and .Token.person .Token.device .Token.tier) }}{{ fail "token must carry person, device, tier" }}{{ end }}
{{- if not (has .Token.tier .AllowedTiers) }}{{ fail "tier not allowed for this provisioner" }}{{ end }}
{
  "subject": {"commonName": {{ toJson .Token.device }}},
  "uris": [
    {{ toJson (printf "urn:cvc:person:%s" .Token.person) }},
    {{ toJson (printf "urn:cvc:device:%s" .Token.device) }},
    {{ toJson (printf "urn:cvc:tier:%s" .Token.tier) }}
  ],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}
