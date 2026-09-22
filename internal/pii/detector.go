package pii

// Detector identifies PII fragments in a text.
type Detector interface {
	Name() string
	Categories() []Category
	Detect(text string) []Span
}

// LowerDetector is an optional extension of Detector. A detector that
// implements it receives a Text with a precomputed Lower field, avoiding
// repeated strings.ToLower calls. The pipeline calls DetectLower when the
// detector implements it, otherwise it falls back to Detect(raw).
type LowerDetector interface {
	DetectLower(t Text) []Span
}

// Registry holds a set of detectors.
type Registry struct {
	detectors []Detector
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a detector to the registry.
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// All returns all registered detectors.
func (r *Registry) All() []Detector {
	return r.detectors
}

// Enabled returns only detectors that produce at least one of the given categories.
func (r *Registry) Enabled(categories []Category) []Detector {
	wanted := make(map[Category]bool, len(categories))
	for _, c := range categories {
		wanted[c] = true
	}
	var out []Detector
	for _, d := range r.detectors {
		for _, c := range d.Categories() {
			if wanted[c] {
				out = append(out, d)
				break
			}
		}
	}
	return out
}
