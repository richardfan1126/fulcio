aws sts get-web-identity-token \
    --audience sigstore \
    --signing-algorithm ES384 | \
    jq -jr ".WebIdentityToken" > token.txt

cosign sign \
    --yes \
    --fulcio-url http://localhost:5555 \
    --insecure-skip-verify \
    --identity-token token.txt \
    --upload=false \
    --tlog-upload=false \
    --output-certificate=demo.crt \
    alpine


openssl x509 \
    -in demo.crt \
    -noout \
    -text