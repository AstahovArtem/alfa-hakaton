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
}

var cardholderContext = []string{
	"держатель", "владелец карты", "cardholder", "card holder", "name on card", "имя на карте",
}

var cardNumRe = regexp.MustCompile(`(?:\d[ -]?){13,19}`)

func (d *cardholderDetector) Detect(text string) []pii.Span {
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
		if i+2 < len(cands) && onlyWhitespace(text, toks[cands[i]].end, toks[cands[i+1]].start) &&
			onlyWhitespace(text, toks[cands[i+1]].end, toks[cands[i+2]].start) {
			seq := []token{toks[cands[i]], toks[cands[i+1]], toks[cands[i+2]]}
			if d.validCardholder(seq, text, hasCard) {
				spans = append(spans, pii.Span{Start: seq[0].start, End: seq[2].end, Category: pii.CatCardHolder, Detector: d.Name(), Confidence: 0.85})
				i += 3
				continue
			}
		}
		if i+1 < len(cands) && onlyWhitespace(text, toks[cands[i]].end, toks[cands[i+1]].start) {
			seq := []token{toks[cands[i]], toks[cands[i+1]]}
			if d.validCardholder(seq, text, hasCard) {
				spans = append(spans, pii.Span{Start: seq[0].start, End: seq[1].end, Category: pii.CatCardHolder, Detector: d.Name(), Confidence: 0.85})
				i += 2
				continue
			}
		}
		i++
	}
	return spans
}

// isCardholderWord reports whether s is a Latin word of 2+ letters or a single
// Latin letter (a middle initial). Case is not restricted here; the case logic
// is applied in validCardholder.
func isCardholderWord(s string) bool {
	if cardholderStop[strings.ToUpper(s)] {
		return false
	}
	if s == "" {
		return false
	}
	letterCount := 0
	for _, r := range s {
		if !isLatinLetter(r) {
			return false
		}
		letterCount++
	}
	return letterCount >= 1
}

func (d *cardholderDetector) validCardholder(seq []token, text string, hasCard bool) bool {
	hasLong := false
	allUpper := true
	for _, t := range seq {
		if len([]rune(t.text)) >= 2 {
			hasLong = true
		}
		if !isAllUpper(t.text) {
			allUpper = false
		}
	}
	if !hasLong {
		return false
	}
	if allUpper && hasCard {
		return true
	}
	if hasLeftContext(text, seq[0].start, cardholderContext, 30) {
		return true
	}
	if hasRightContext(text, seq[len(seq)-1].end, cardholderContext, 30) {
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
