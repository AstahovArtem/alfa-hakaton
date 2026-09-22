package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

// citizenshipContext are the keywords that introduce a citizenship value.
var citizenshipContext = []string{
	"гражданство", "гражданин", "гражданка", "citizenship",
}

// citizenshipSkip are words that may appear between the context keyword and the
// country value (e.g. "Гражданство заявителя: Таджикистан").
var citizenshipSkip = []string{
	"заявителя", "клиента", "заявитель", "клиент",
}

// countryForms maps a canonical country name to its inflected forms (lowercase).
// The forms are matched against the lowercased text.
var countryForms = map[string][]string{
	"россия": {"россия", "россии", "россию", "россией", "российская"},
	"рф":     {"рф"},
	"российская федерация":  {"российская федерация", "российской федерации", "российской федерацией"},
	"казахстан":             {"казахстан", "казахстана", "казахстане", "казахстаном"},
	"беларусь":              {"беларусь", "беларуси", "беларусью"},
	"белоруссия":            {"белоруссия", "белоруссии"},
	"узбекистан":            {"узбекистан", "узбекистана", "узбекистане"},
	"таджикистан":           {"таджикистан", "таджикистана", "таджикистане"},
	"киргизия":              {"киргизия", "киргизии"},
	"кыргызстан":            {"кыргызстан", "кыргызстана"},
	"кыргызская республика": {"кыргызская республика", "кыргызской республики", "кыргызской республикой"},
	"армения":               {"армения", "армении", "армению"},
	"азербайджан":           {"азербайджан", "азербайджана", "азербайджане"},
	"грузия":                {"грузия", "грузии"},
	"молдова":               {"молдова", "молдовы", "молдове"},
	"украина":               {"украина", "украины", "украине"},
	"туркменистан":          {"туркменистан", "туркменистана"},
	"вьетнам":               {"вьетнам", "вьетнама", "вьетнаме"},
	"китай":                 {"китай", "китая", "китае"},
	"кнр":                   {"кнр"},
	"китайская народная республика": {"китайская народная республика", "китайской народной республики"},
	"корея":            {"корея", "кореи"},
	"республика корея": {"республика корея", "республики корея"},
	"турция":           {"турция", "турции"},
	"индия":            {"индия", "индии"},
	"сша":              {"сша"},
	"германия":         {"германия", "германии"},
	"израиль":          {"израиль", "израиля"},
	"румыния":          {"румыния", "румынии"},
	"социалистическая республика вьетнам": {"социалистическая республика вьетнам", "социалистической республики вьетнам"},
	"azerbaijani": {"azerbaijani"},
	"russian":     {"russian"},
	"kazakh":      {"kazakh"},
	"uzbek":       {"uzbek"},
	"tajik":       {"tajik"},
	"armenian":    {"armenian"},
	"georgian":    {"georgian"},
	"moldovan":    {"moldovan"},
	"ukrainian":   {"ukrainian"},
	"turkmen":     {"turkmen"},
	"vietnamese":  {"vietnamese"},
	"chinese":     {"chinese"},
	"korean":      {"korean"},
	"turkish":     {"turkish"},
	"indian":      {"indian"},
	"german":      {"german"},
	"israeli":     {"israeli"},
	"belarusian":  {"belarusian"},
	"kyrgyz":      {"kyrgyz"},
}

// countryFormList is the flattened list of all country forms, longest first so
// that multi-word forms are matched before their single-word prefixes.
var countryFormList = buildCountryFormList()

func buildCountryFormList() []string {
	var forms []string
	for _, fs := range countryForms {
		forms = append(forms, fs...)
	}
	// Sort by length descending so longer phrases match first.
	for i := 1; i < len(forms); i++ {
		for j := i; j > 0 && len(forms[j]) > len(forms[j-1]); j-- {
			forms[j], forms[j-1] = forms[j-1], forms[j]
		}
	}
	return forms
}

// republicRe matches "республика <word>" in any case, e.g. "Республики Армения".
var republicRe = regexp.MustCompile(`республик[аиуойе]?\s+[а-яё]+`)

// citizenshipValueRe matches the value after a citizenship context keyword. It
// captures the country value, skipping separators and filler words.
var citizenshipValueRe = regexp.MustCompile(`^\s*:?\s*(?:—\s*)?(?:заявителя\s*:?\s*|клиента\s*:?\s*)?`)

type citizenshipDetector struct{}

// NewCitizenshipDetector builds the citizenship detector.
func NewCitizenshipDetector() pii.Detector {
	return &citizenshipDetector{}
}

func (d *citizenshipDetector) Name() string { return "citizenship" }

func (d *citizenshipDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatCitizenship}
}

func (d *citizenshipDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *citizenshipDetector) DetectLower(t pii.Text) []pii.Span {
	lower := t.Lower
	if !t.LowerOK() {
		lower = strings.ToLower(t.Raw)
	}
	var spans []pii.Span
	for _, kw := range citizenshipContext {
		idx := 0
		for {
			pos := strings.Index(lower[idx:], kw)
			if pos < 0 {
				break
			}
			start := idx + pos
			// The keyword must be a whole word.
			if start > 0 && isLetterRune(rune(t.Raw[start-1])) {
				idx = start + len(kw)
				continue
			}
			if end := start + len(kw); end < len(lower) && isLetterRune(rune(t.Raw[end])) {
				idx = start + len(kw)
				continue
			}
			if span, ok := d.matchValue(t, lower, start+len(kw)); ok {
				spans = append(spans, span)
			}
			// English "X citizenship": the country precedes the keyword.
			if kw == "citizenship" {
				if span, ok := d.matchBefore(t, lower, start); ok {
					spans = append(spans, span)
				}
			}
			idx = start + len(kw)
		}
	}
	// Dialog form: a country on its own line that answers a question containing
	// "гражданств".
	spans = append(spans, d.matchDialog(t, lower)...)
	return spans
}

// matchValue extracts the country value immediately after a context keyword.
func (d *citizenshipDetector) matchValue(t pii.Text, lower string, after int) (pii.Span, bool) {
	rest := lower[after:]
	// Skip separators and filler words.
	skipped := 0
	if m := citizenshipValueRe.FindStringIndex(rest); m != nil {
		skipped = m[1]
		rest = rest[m[1]:]
	}
	// Match the longest country form.
	bestLen := 0
	for _, form := range countryFormList {
		if strings.HasPrefix(rest, form) {
			if len(form) > bestLen {
				bestLen = len(form)
			}
		}
	}
	// Match "республика <word>" generically.
	if loc := republicRe.FindStringIndex(rest); loc != nil && loc[0] == 0 {
		if loc[1] > bestLen {
			bestLen = loc[1]
		}
	}
	if bestLen == 0 {
		return pii.Span{}, false
	}
	// Compute the byte offset of the value start in the raw text.
	valStart := after + skipped
	valEnd := valStart + bestLen
	return pii.Span{
		Start:      valStart,
		End:        valEnd,
		Category:   pii.CatCitizenship,
		Detector:   d.Name(),
		Confidence: 0.9,
	}, true
}

// matchBefore extracts a country value that precedes a context keyword, as in
// the English form "holds Azerbaijani citizenship".
func (d *citizenshipDetector) matchBefore(t pii.Text, lower string, kwStart int) (pii.Span, bool) {
	before := lower[:kwStart]
	// Find the longest country form ending at the keyword.
	bestStart := -1
	bestLen := 0
	for _, form := range countryFormList {
		idx := strings.LastIndex(before, form)
		if idx < 0 {
			continue
		}
		// The form must end at the keyword (only whitespace between).
		after := before[idx+len(form):]
		if strings.TrimSpace(after) != "" {
			continue
		}
		if len(form) > bestLen {
			bestLen = len(form)
			bestStart = idx
		}
	}
	if bestStart < 0 {
		return pii.Span{}, false
	}
	return pii.Span{
		Start:      bestStart,
		End:        bestStart + bestLen,
		Category:   pii.CatCitizenship,
		Detector:   d.Name(),
		Confidence: 0.9,
	}, true
}

// matchDialog detects a country on its own line that answers a question
// containing "гражданств".
func (d *citizenshipDetector) matchDialog(t pii.Text, lower string) []pii.Span {
	var spans []pii.Span
	lines := strings.Split(lower, "\n")
	offset := 0
	for i, line := range lines {
		if strings.Contains(line, "гражданств") && strings.Contains(line, "?") {
			// Look at the next line for a country.
			if i+1 < len(lines) {
				next := lines[i+1]
				// Strip a speaker prefix like "клиент:".
				val := next
				if c := strings.Index(val, ":"); c >= 0 {
					val = val[c+1:]
				}
				val = strings.TrimSpace(val)
				for _, form := range countryFormList {
					if strings.HasPrefix(val, form) {
						// The next line starts at offset + len(line) + 1 (for the
						// newline); the value sits len(next)-len(val) bytes into it.
						lineStart := offset + len(line) + 1 + (len(next) - len(val))
						spans = append(spans, pii.Span{
							Start:      lineStart,
							End:        lineStart + len(form),
							Category:   pii.CatCitizenship,
							Detector:   d.Name(),
							Confidence: 0.9,
						})
						break
					}
				}
			}
		}
		offset += len(line) + 1
	}
	return spans
}
