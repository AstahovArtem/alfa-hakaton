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
	return Result{Spans: postProcess(Resolve(spans))}
}

// postProcess applies cross-span reclassification rules that depend on the
// resolved span set. A bare date that immediately follows a passport_issuer
// span is reclassified to passport_date.
func postProcess(spans []Span) []Span {
	for i := range spans {
		if spans[i].Category != CatDate {
			continue
		}
		for j := range spans {
			if spans[j].Category != CatPassportIssuer {
				continue
			}
			if spans[i].Start >= spans[j].Start && spans[i].Start-spans[j].End <= 3 {
				spans[i].Category = CatPassportDate
				break
			}
		}
	}
	return spans
}
