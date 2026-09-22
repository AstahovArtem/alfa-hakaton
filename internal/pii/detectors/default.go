package detectors

import "pdn-shield/internal/pii"

// Default returns the list of default detectors.
func Default() []pii.Detector {
	rules, err := DefaultRules()
	if err != nil {
		// Embedded rules must always load; a failure is a programming error.
		panic(err)
	}
	return []pii.Detector{
		NewRegexDetector(rules),
		NewNamesDetector(),
		NewCardholderDetector(),
		NewAddressDetector(),
		NewBirthplaceDetector(),
		NewCitizenshipDetector(),
		NewIssuerDetector(),
	}
}
