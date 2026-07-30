package sdwit

import (
	"errors"
	"strings"
)

// Present creates a selective presentation of an SD-JWT by keeping only the
// disclosures for the named claims. The Issuer-signed JWT is unchanged.
//
// The returned string is a valid SD-JWT that a Verifier can parse: it will
// see the always-visible claims (iss, exp, cnf, aud, ...) plus only the
// explicitly revealed claims. Claims whose disclosures are dropped are
// invisible to the Verifier — their hashes remain in _sd, but without the
// disclosure the Verifier cannot learn their values.
//
// revealClaims is a slice of claim names to include (e.g. []string{"sub"}).
// To reveal all disclosures, pass nil (or use the original SD-JWT directly).
func Present(sdJWT string, revealClaims []string) (string, error) {
	signedJWT, disclosures, err := splitSDJWT(sdJWT)
	if err != nil {
		return "", err
	}
	if len(disclosures) == 0 {
		// Nothing to filter.
		return sdJWT, nil
	}

	revealSet := map[string]bool{}
	for _, c := range revealClaims {
		revealSet[c] = true
	}

	var kept []string
	for _, disc := range disclosures {
		_, name, _, err := decodeDisclosure(disc)
		if err != nil {
			return "", err
		}
		if revealSet[name] {
			kept = append(kept, disc)
		}
	}

	parts := append([]string{signedJWT}, kept...)
	parts = append(parts, "") // trailing tilde
	return strings.Join(parts, "~"), nil
}

// RevealedClaims returns the claim names visible in a given SD-JWT presentation —
// i.e. all claim names for which a disclosure is included in this string.
// Useful for debugging or for letting the Holder confirm what a presentation reveals.
func RevealedClaims(sdJWT string) ([]string, error) {
	_, disclosures, err := splitSDJWT(sdJWT)
	if err != nil {
		return nil, err
	}
	if len(disclosures) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(disclosures))
	seen := map[string]bool{}
	for _, disc := range disclosures {
		_, name, _, err := decodeDisclosure(disc)
		if err != nil {
			return nil, err
		}
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names, nil
}

// FullPresentation returns a copy of the SD-JWT with all disclosures included.
// If the token already contains all disclosures (as issued), this is a no-op.
func FullPresentation(sdJWT string) (string, error) {
	_, disclosures, err := splitSDJWT(sdJWT)
	if err != nil {
		return "", err
	}
	if len(disclosures) == 0 && !strings.HasSuffix(sdJWT, "~") {
		return "", errors.New("token has no disclosures and is not an SD-JWT")
	}
	return sdJWT, nil
}
