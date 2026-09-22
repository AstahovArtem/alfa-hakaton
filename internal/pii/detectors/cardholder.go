package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

type cardholderDetector struct{}

// NewCardholderDetector builds the card_holder detector.
func NewCardholderDetector() pii.Detector {
	return &cardholderDetector{}
}

func (d *cardholderDetector) Name() string { return "cardholder" }

func (d *cardholderDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatCardHolder}
}

var cardholderStop = map[string]bool{
	"VISA": true, "MASTERCARD": true, "MIR": true, "CVV": true, "CVC": true,
	"PIN": true, "LLC": true, "LTD": true, "OOO": true, "PAO": true, "AO": true,
	"INN": true, "USD": true, "EUR": true, "RUB": true,
	"CARD": true, "VALID": true, "THRU": true, "EXP": true, "NO": true,
}

var cardholderContext = []string{
	"держатель", "держателя", "держателю", "держателем", "владелец карты", "cardholder", "card holder",
	"name on card", "имя на карте", "имя держателя", "на имя", "эмбоссированное имя", "cardholder:",
}

var cardNumRe = regexp.MustCompile(`(?:\d[ -]?){13,19}`)

func (d *cardholderDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *cardholderDetector) DetectLower(t pii.Text) []pii.Span {
	text := t.Raw
	toks := tokenize(text)
	var cands []int
	for i := range toks {
		if isCardholderWord(toks[i].text) {
			cands = append(cands, i)
		}
	}
	hasCard := hasCardNumber(text)
	var spans []pii.Span
	i := 0
	for i < len(cands) {
		if span, adv := d.tryThree(text, toks, cands, i, t, hasCard); adv > 0 {
			spans = append(spans, span)
			i += adv
			continue
		}
		if span, adv := d.tryTwo(text, toks, cands, i, t, hasCard); adv > 0 {
			spans = append(spans, span)
			i += adv
			continue
		}
		i++
	}
	return spans
}

// tryThree attempts to emit a three-token cardholder span starting at candidate
// index i. It returns the span and the number of candidate indices to advance
// (0 when no span is emitted).
func (d *cardholderDetector) tryThree(
	text string,
	toks []token,
	cands []int,
	i int,
	t pii.Text,
	hasCard bool,
) (pii.Span, int) {
	if i+2 >= len(cands) ||
		!onlyWhitespace(text, toks[cands[i]].end, toks[cands[i+1]].start) ||
		!onlyWhitespace(text, toks[cands[i+1]].end, toks[cands[i+2]].start) {
		return pii.Span{}, 0
	}
	seq := []token{toks[cands[i]], toks[cands[i+1]], toks[cands[i+2]]}
	if !d.validCardholder(seq, t, hasCard) {
		return pii.Span{}, 0
	}
	return pii.Span{
		Start:      seq[0].start,
		End:        seq[2].end,
		Category:   pii.CatCardHolder,
		Detector:   d.Name(),
		Confidence: cardholderConfidence(seq, t, hasCard),
	}, 3
}

// tryTwo attempts to emit a two-token cardholder span starting at candidate
// index i. It returns the span and the number of candidate indices to advance
// (0 when no span is emitted).
func (d *cardholderDetector) tryTwo(
	text string,
	toks []token,
	cands []int,
	i int,
	t pii.Text,
	hasCard bool,
) (pii.Span, int) {
	if i+1 >= len(cands) || !onlyWhitespace(text, toks[cands[i]].end, toks[cands[i+1]].start) {
		return pii.Span{}, 0
	}
	seq := []token{toks[cands[i]], toks[cands[i+1]]}
	if !d.validCardholder(seq, t, hasCard) {
		return pii.Span{}, 0
	}
	return pii.Span{
		Start:      seq[0].start,
		End:        seq[1].end,
		Category:   pii.CatCardHolder,
		Detector:   d.Name(),
		Confidence: cardholderConfidence(seq, t, hasCard),
	}, 2
}

// isCardholderWord reports whether s is a Latin word of 2+ letters or a single
// Latin letter (a middle initial). Inner hyphens are allowed so hyphenated
// surnames (e.g. "VOLKOVA-BRANDT") are treated as a single word. Case is not
// restricted here; the case logic is applied in validCardholder.
func isCardholderWord(s string) bool {
	if cardholderStop[strings.ToUpper(s)] {
		return false
	}
	if s == "" {
		return false
	}
	letterCount := 0
	for i, r := range s {
		if isLatinLetter(r) {
			letterCount++
			continue
		}
		// Allow an inner hyphen between two letters.
		if r == '-' && i > 0 && i < len(s)-1 {
			continue
		}
		return false
	}
	return letterCount >= 1
}

func (d *cardholderDetector) validCardholder(seq []token, t pii.Text, hasCard bool) bool {
	hasLong := false
	allUpper := true
	for _, tok := range seq {
		if len([]rune(tok.text)) >= 2 {
			hasLong = true
		}
		if !isAllUpper(tok.text) {
			allUpper = false
		}
	}
	if !hasLong {
		return false
	}
	if allUpper && hasCard {
		return true
	}
	if hasLeftContext(t, seq[0].start, cardholderContext, 30) {
		return true
	}
	if hasRightContext(t, seq[len(seq)-1].end, cardholderContext, 30) {
		return true
	}
	return false
}

func isAllUpper(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isLatinLetter(r) || r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// cardholderConfidence returns the confidence for a cardholder span. An
// all-uppercase name alongside a card number or a cardholder context keyword is
// a strong signal (embossed cardholder), so it outranks a competing full_name
// span.
func cardholderConfidence(seq []token, t pii.Text, hasCard bool) float64 {
	allUpper := true
	for _, tok := range seq {
		if !isAllUpper(tok.text) {
			allUpper = false
			break
		}
	}
	if allUpper && (hasCard || hasLeftContext(t, seq[0].start, cardholderContext, 30)) {
		return 0.95
	}
	return 0.85
}

// hasCardNumber reports whether the text contains a 13-19 digit sequence
// (with optional separators) that passes the Luhn check.
func hasCardNumber(text string) bool {
	for _, m := range cardNumRe.FindAllString(text, -1) {
		if luhn(m) {
			return true
		}
	}
	return false
}
