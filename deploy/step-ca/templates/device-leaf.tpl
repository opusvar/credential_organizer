{{- /* Device leaf. Identity SANs come ONLY from signed token claims (.Token),
       never from the CSR. Used by the issuer-* JWK provisioners. */ -}}
{{- if not (and .Token.person .Token.device .Token.tier) }}{{ fail "token must carry person, device, tier" }}{{ end }}
{{- if not (has .Token.tier .AllowedTiers) }}{{ fail "tier not allowed for this provisioner" }}{{ end }}
{{- /* Bridge (temporary device, D27): tier capped at medium. */ -}}
{{- if and .Token.temp (not (has .Token.tier (list "media-only" "low" "medium"))) }}{{ fail "temp device tier above medium" }}{{ end }}
{
  "subject": {"commonName": {{ toJson .Token.device }}},
  "uris": [
    {{ toJson (printf "urn:cvc:person:%s" .Token.person) }},
    {{ toJson (printf "urn:cvc:device:%s" .Token.device) }},
    {{ toJson (printf "urn:cvc:tier:%s" .Token.tier) }}
    {{- if .Token.temp }},
    {{ toJson (printf "urn:cvc:temp:%s" .Token.temp) }}
    {{- end }}
  ],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}
