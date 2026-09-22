//go:build !race

package pii_test

// raceEnabled reports whether the race detector is active. Under -race the
// pipeline runs far slower, so absolute timing thresholds are relaxed while the
// linear-scaling ratio check is still enforced.
const raceEnabled = false
