package detectors

import (
	"regexp"
	"strings"

	"pdn-shield/internal/pii"
)

var issuerContextRe = regexp.MustCompile(
	`(?i)(?:^|[^\p{L}])(кем выдан|выдавший орган|орган выдачи|орган, выдавший|дата выдачи|выдано|выдана|выдан|выдали|выдачи|получал|получала|получил|получила|получен|получена|кем|орган)(?:[^\p{L}]|$)`,
)

// issuerStartWordRe matches the first word of an issuing authority value. It is
// searched for after a context keyword, allowing a gap of non-letter text (and
// dialogue labels) between the context and the value.
var issuerStartWordRe = regexp.MustCompile(
	`(?i)(паспортным столом|межрайонным|отделением|отделении|отделения|отделом|отделе|отдел|управлением|управления|управление|миграционным|миграционной|паспортно-визовым|паспортным|паспортного|гу мвд|гувд|оуфмс|уфмс|омвд|умвд|увд|овд|мвд|милиции|о/м|тп|оп|мп)`,
)

// issuerGapRe matches the text that may sit between a context keyword and the
// issuing authority value: non-Cyrillic runs (whitespace, digits, dates,
// punctuation) and dialogue labels such as "клиент:" / "оператор:".
var issuerGapRe = regexp.MustCompile(`(?i)^(?:[^а-яёА-ЯЁ]+|клиент\s*:\s*|оператор\s*:\s*)*`)

var issuerTermRe = regexp.MustCompile(
	`(?i)(?:\n|;|\d{1,2}[./-]\d{1,2}[./-]\d{4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}|\d{1,2}\s+(?:янв|фев|мар|апр|мая|май|июн|июл|авг|сен|сент|окт|ноя|дек)\.?\s+\d{4}|код подразделения|к/п|дата выдачи|выдан|гражданство)`,
)

// Lowercase-only variants matched against the lowercased text to avoid
// case-folding cost.
var issuerContextLowerRe = regexp.MustCompile(
	`(?:^|[^\p{L}])(кем выдан|выдавший орган|орган выдачи|орган, выдавший|дата выдачи|выдано|выдана|выдан|выдали|выдачи|получал|получала|получил|получила|получен|получена|кем|орган)(?:[^\p{L}]|$)`,
)

var issuerStartWordLowerRe = regexp.MustCompile(
	`(паспортным столом|межрайонным|отделением|отделении|отделения|отделом|отделе|отдел|управлением|управления|управление|миграционным|миграционной|паспортно-визовым|паспортным|паспортного|гу мвд|гувд|оуфмс|уфмс|омвд|умвд|увд|овд|мвд|милиции|о/м|тп|оп|мп)`,
)

var issuerGapLowerRe = regexp.MustCompile(`^(?:[^а-яёА-ЯЁ]+|клиент\s*:\s*|оператор\s*:\s*)*`)

// issuerGapWordRe matches the Cyrillic words and dates-in-words that may sit
// between a context keyword and the issuing authority value: the filler words
// "в", "г.", "гор.", "мне", "был", "была", "паспорт", dialogue labels and full
// dates written in words. Any other Cyrillic text in the gap is rejected. The
// filler words are matched as whole words so "г" does not match inside "ГУ".
var issuerGapWordRe = regexp.MustCompile(
	`(?i)(?:в|г\.?|гор\.?|мне|был|была|паспорт)(?:[^\p{L}]|$)|клиент\s*:\s*|оператор\s*:\s*|` + dateWordsRe.String(),
)

// issuerOrganKeywordRe matches the keywords that confirm an "отделение/отдел"
// start word is an issuing authority rather than a bank/post/medical branch.
// Each keyword is matched as a whole word so "по" does not match inside
// "почты" or "полиции".
var issuerOrganKeywordRe = regexp.MustCompile(
	`(?i)(?:^|[^\p{L}])(?:уфмс|мвд|овд|увд|омвд|умвд|милиции|полиции|россии|района|р-на|города|г\.|по|№)(?:[^\p{L}]|$)`,
)

var issuerTermLowerRe = regexp.MustCompile(
	`(?:\n|;|\d{1,2}[./-]\d{1,2}[./-]\d{4}|\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{4}|\d{1,2}\s+(?:янв|фев|мар|апр|мая|май|июн|июл|авг|сен|сент|окт|ноя|дек)\.?\s+\d{4}|код подразделения|к/п|дата выдачи|выдан|гражданство)`,
)

// issuerAbbrevs are abbreviations whose trailing period is not a sentence end.
var issuerAbbrevs = map[string]bool{
	"г": true, "ул": true, "д": true, "кв": true, "пр": true, "пер": true,
	"обл": true, "респ": true, markerStr: true, markerKorp: true, "оф": true,
	"пом": true, "комн": true, "пос": true, "дер": true, "ст": true,
	wordGorod: true, "наб": true, "пл": true, "ш": true, "р-н": true, "пгт": true,
	"т": true, "др": true, "пр-т": true, "пр-д": true, "б-р": true,
}

// issuerContinuations are words that may follow a comma and still belong to the
// issuing authority name (e.g. "по г. Москве, отделом по району Хамовники").
var issuerContinuations = map[string]bool{
	"по": true, "в": true, "и": true, "г": true, wordGorod: true, wordRaion: true,
	"района": true, "области": true, "отдел": true, "отделом": true,
	"отделение": true, "отделением": true, "тп": true, "№": true,
	wordKrai: true, "края": true, "округ": true, "округа": true,
}

// issuerAlwaysEnd are words that always terminate the issuing authority value.
var issuerAlwaysEnd = map[string]bool{
	"копия": true, "приложена": true, "документ": true, "дата": true, "код": true,
}

type issuerDetector struct{}

// NewIssuerDetector builds the passport_issuer detector.
func NewIssuerDetector() pii.Detector {
	return &issuerDetector{}
}

func (d *issuerDetector) Name() string { return "issuer" }

func (d *issuerDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatPassportIssuer}
}

func (d *issuerDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *issuerDetector) DetectLower(t pii.Text) []pii.Span {
	text := t.Raw
	search := text
	ctxRe, startRe, gapRe, termRe := issuerContextRe, issuerStartWordRe, issuerGapRe, issuerTermRe
	if t.LowerOK() {
		search = t.Lower
		ctxRe, startRe, gapRe, termRe = issuerContextLowerRe, issuerStartWordLowerRe, issuerGapLowerRe, issuerTermLowerRe
	}
	var spans []pii.Span
	for _, loc := range ctxRe.FindAllStringSubmatchIndex(search, -1) {
		ctxEnd := loc[3]
		start := findIssuerStart(search, ctxEnd, startRe, gapRe)
		if start < 0 {
			continue
		}
		end := issuerEnd(text, search, start, termRe)
		value := search[start:end]
		value = strings.TrimRight(value, " ,.")
		end = start + len(value)
		if value == "" {
			continue
		}
		spans = append(spans, pii.Span{
			Start:      start,
			End:        end,
			Category:   pii.CatPassportIssuer,
			Detector:   d.Name(),
			Confidence: 0.9,
		})
	}
	return spans
}

// findIssuerStart returns the byte offset where the issuing authority value
// begins, scanning forward from from for the first start word. A gap of
// non-letter text (whitespace, digits, dates, punctuation), dialogue labels,
// filler words and dates-in-words may sit between the context keyword and the
// value. It returns -1 when no start word is found within a window of 300
// runes, when the gap contains other Cyrillic text, or when an "отделение/отдел"
// start word is not followed by an organ keyword.
func findIssuerStart(search string, from int, startRe, gapRe *regexp.Regexp) int {
	windowEnd := runeOffsetAfter(search, from, 300)
	pos := from
	for pos < windowEnd {
		next := consumeIssuerGap(search, pos, windowEnd, gapRe)
		if next > pos {
			pos = next
			continue
		}
		m := startRe.FindStringIndex(search[pos:windowEnd])
		if m == nil || m[0] > 0 {
			// No start word, or a start word not at the current position means
			// the gap contains text that is neither allowed gap content nor a
			// start word: reject it.
			return -1
		}
		start := pos + m[0]
		if !issuerStartValid(search, start) {
			return -1
		}
		// Include a leading number that is part of the issuing authority value
		// (e.g. "16 о/м Центрального р-на" keeps the "16").
		return issuerStartWithNumber(search, start)
	}
	return -1
}

// consumeIssuerGap advances pos over allowed gap content (non-letter runs,
// dialogue labels, filler words and dates-in-words) and returns the new
// position. It returns pos unchanged when no allowed gap content starts at pos.
func consumeIssuerGap(search string, pos, windowEnd int, gapRe *regexp.Regexp) int {
	if loc := gapRe.FindStringIndex(search[pos:windowEnd]); loc != nil && loc[1] > 0 {
		return pos + loc[1]
	}
	if loc := issuerGapWordRe.FindStringIndex(search[pos:windowEnd]); loc != nil && loc[0] == 0 && loc[1] > 0 {
		return pos + loc[1]
	}
	return pos
}

// issuerStartValid reports whether the start word at start is an acceptable
// issuing authority. An "отделение/отдел" start word is only accepted when an
// organ keyword (уфмс, мвд, овд, ...) appears within 40 runes ahead; otherwise
// it is a bank/post/medical branch, not an issuing authority.
func issuerStartValid(search string, start int) bool {
	word := strings.ToLower(nextWord(search, start))
	if !strings.HasPrefix(word, "отдел") {
		return true
	}
	windowEnd := runeOffsetAfter(search, start, 40)
	return issuerOrganKeywordRe.MatchString(search[start:windowEnd])
}

// issuerStartWithNumber extends start backward to include a number that
// immediately precedes the issuing authority word (e.g. "16 о/м").
func issuerStartWithNumber(search string, start int) int {
	// Look back for a number separated by a single space.
	i := start - 1
	if i < 0 || search[i] != ' ' {
		return start
	}
	j := i
	for j > 0 && search[j-1] >= '0' && search[j-1] <= '9' {
		j--
	}
	if j == i {
		return start
	}
	return j
}

// issuerEnd returns the byte offset where the issuer value ends, scanning from
// start for the earliest terminator (sentence end, date, keyword, newline) and
// capping the value at 12 words. raw is the original text (used for the
// uppercase sentence-end check); text is the text the terminator regexes run
// against (the lowercased text when byte lengths match). The search is limited
// to a window of 300 runes from start so the cost stays linear in the number of
// issuer contexts rather than quadratic in the text length.
func issuerEnd(raw, text string, start int, termRe *regexp.Regexp) int {
	windowEnd := runeOffsetAfter(text, start, 300)
	end := windowEnd
	for _, tloc := range termRe.FindAllStringIndex(text[start:windowEnd], -1) {
		pos := start + tloc[0]
		if pos < end {
			end = pos
		}
	}
	end = issuerEndAtPeriod(raw, text, start, end)
	end = issuerEndAtComma(text, start, end)
	// Cap at 16 words.
	words := strings.Fields(text[start:end])
	if len(words) > 16 {
		cut := start
		for k := 0; k < 16; k++ {
			idx := strings.Index(text[cut:], words[k])
			cut += idx + len(words[k])
		}
		if cut < end {
			end = cut
		}
	}
	return end
}

// issuerEndAtPeriod trims the value at a sentence-ending period (not an
// abbreviation) followed by whitespace+capital or the end of the text. It only
// scans within [start, end).
func issuerEndAtPeriod(raw, text string, start, end int) int {
	for i := start; i < end; i++ {
		if text[i] != '.' || isAbbrevPeriod(text, i) {
			continue
		}
		if sentenceEnd(raw, text, i) && i < end {
			end = i
		}
	}
	return end
}

// sentenceEnd reports whether the period at pos ends a sentence: it is the last
// byte of the text or is followed by whitespace and an uppercase letter.
func sentenceEnd(raw, text string, pos int) bool {
	if pos+1 == len(text) {
		return true
	}
	return text[pos+1] == ' ' && pos+2 < len(text) && isUpperRune(decodedRune(raw, pos+2))
}

// issuerEndAtComma trims the value at a comma when the following word is not a
// continuation of the issuing authority. It only scans within [start, end).
func issuerEndAtComma(text string, start, end int) int {
	for i := start; i < end; i++ {
		if text[i] != ',' {
			continue
		}
		if commaEndsValue(text, i) && i < end {
			end = i
		}
	}
	return end
}

// commaEndsValue reports whether the comma at pos terminates the value, i.e.
// the following word is not a continuation of the issuing authority.
func commaEndsValue(text string, pos int) bool {
	next := nextWord(text, pos+1)
	if next == "" {
		return false
	}
	lower := strings.ToLower(next)
	return issuerAlwaysEnd[lower] || !issuerContinuations[lower]
}

// isAbbrevPeriod reports whether the period at pos is part of an abbreviation.
func isAbbrevPeriod(text string, pos int) bool {
	// Find the token start before the period.
	tokEnd := pos
	tokStart := tokEnd
	for tokStart > 0 && text[tokStart-1] != ' ' && text[tokStart-1] != '\n' {
		tokStart--
	}
	tok := strings.ToLower(text[tokStart:tokEnd])
	return issuerAbbrevs[tok]
}

// nextWord returns the first whitespace-delimited word at or after pos, or "".
func nextWord(text string, pos int) string {
	for pos < len(text) && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n') {
		pos++
	}
	start := pos
	for pos < len(text) && !isWordBoundary(text[pos]) {
		pos++
	}
	return text[start:pos]
}

// isWordBoundary reports whether b terminates a word.
func isWordBoundary(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == ','
}
