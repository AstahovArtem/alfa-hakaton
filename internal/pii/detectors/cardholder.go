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
	"name on card", "имя на карте", "имя держателя", ctxNaImya, "эмбоссированное имя", "cardholder:",
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
		// Try the longest run first (up to 4 words, e.g. "JOHN RONALD REUEL
		// TOLKIEN") so a long holder name is covered in one span instead of
		// only its first two or three words.
		adv := 0
		for n := 4; n >= 2; n-- {
			if span, ok := d.tryN(text, toks, cands, i, t, hasCard, n); ok {
				spans = append(spans, span)
				adv = n
				break
			}
		}
		if adv == 0 {
			i++
			continue
		}
		i += adv
	}
	return spans
}

// tryN attempts to emit an n-token (2-4) cardholder span starting at candidate
// index i. It returns the span and whether one was emitted.
func (d *cardholderDetector) tryN(
	text string,
	toks []token,
	cands []int,
	i int,
	t pii.Text,
	hasCard bool,
	n int,
) (pii.Span, bool) {
	if i+n-1 >= len(cands) {
		return pii.Span{}, false
	}
	seq := make([]token, n)
	seq[0] = toks[cands[i]]
	for k := 1; k < n; k++ {
		if !onlyWhitespace(text, toks[cands[i+k-1]].end, toks[cands[i+k]].start) {
			return pii.Span{}, false
		}
		seq[k] = toks[cands[i+k]]
	}
	if !d.validCardholder(seq, t, hasCard) {
		return pii.Span{}, false
	}
	return pii.Span{
		Start:      seq[0].start,
		End:        seq[n-1].end,
		Category:   pii.CatCardHolder,
		Detector:   d.Name(),
		Confidence: cardholderConfidence(seq, t, hasCard),
	}, true
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
