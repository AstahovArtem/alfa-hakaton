package pii

import "strings"

// Pipeline runs a set of detectors over a text and resolves the resulting spans.
type Pipeline struct {
	detectors []Detector
}

// NewPipeline creates a pipeline from the given detectors.
func NewPipeline(ds ...Detector) *Pipeline {
	return &Pipeline{detectors: ds}
}

// Run invokes detectors sequentially, collects spans and applies Resolve.
// The text is lowercased once and shared with detectors that implement
// LowerDetector, avoiding repeated strings.ToLower calls.
func (p *Pipeline) Run(text string) Result {
	t := Text{Raw: text, Lower: strings.ToLower(text)}
	var spans []Span
	for _, d := range p.detectors {
		if ld, ok := d.(LowerDetector); ok {
			spans = append(spans, ld.DetectLower(t)...)
		} else {
			spans = append(spans, d.Detect(text)...)
		}
	}
	return Result{Spans: Resolve(spans)}
}
