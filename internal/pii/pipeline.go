package pii

// Pipeline runs a set of detectors over a text and resolves the resulting spans.
type Pipeline struct {
	detectors []Detector
}

// NewPipeline creates a pipeline from the given detectors.
func NewPipeline(ds ...Detector) *Pipeline {
	return &Pipeline{detectors: ds}
}

// Run invokes detectors sequentially, collects spans and applies Resolve.
func (p *Pipeline) Run(text string) Result {
	var spans []Span
	for _, d := range p.detectors {
		spans = append(spans, d.Detect(text)...)
	}
	return Result{Spans: Resolve(spans)}
}
