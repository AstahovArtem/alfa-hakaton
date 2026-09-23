package detectors

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

// Common Russian inflectional suffixes used in name/surname matching.
const (
	sufAmi     = "ами"
	sufImi     = "ими"
	sufYmi     = "ыми"
	sufOgo     = "ого"
	sufOmu     = "ому"
	sufOva     = "ова"
	sufEva     = "ева"
	sufYova    = "ёва"
	sufIna     = "ина"
	sufYna     = "ына"
	sufOvna    = "овна"
	sufEvna    = "евна"
	sufIchna   = "ична"
	sufInichna = "инична"
	sufSkaya   = "ская"
	sufTskaya  = "цкая"
	sufSky     = "ский"
)

// Short Russian inflectional suffixes reused across name/surname matching.
const (
	sufOv  = "ов"
	sufEv  = "ев"
	sufYov = "ёв"
	sufIn  = "ин"
	sufYn  = "ын"
	sufOy  = "ой"
	sufOm  = "ом"
	sufEm  = "ем"
	sufAh  = "ах"
	sufYm  = "ым"
	sufIm  = "им"
	sufEy  = "ей"
	sufIch = "ич"
	sufIy  = "ий"
)

// Dict file names.
const (
	dictFirstNames = "dict/first_names.txt"
	dictSurnames   = "dict/surnames.txt"
)

// Month names in the genitive case.
const (
	monthJanuary   = "января"
	monthFebruary  = "февраля"
	monthMarch     = "марта"
	monthApril     = "апреля"
	monthMay       = "мая"
	monthJune      = "июня"
	monthJuly      = "июля"
	monthAugust    = "августа"
	monthSeptember = "сентября"
	monthOctober   = "октября"
	monthNovember  = "ноября"
	monthDecember  = "декабря"
)

// Name context keywords.
const (
	ctxClient    = "клиент"
	ctxFIO       = "фио"
	ctxZovut     = "зовут"
	ctxRussia    = "россия"
	ctxOtdelenie = "отделение"
	ctxOblast    = "область"
	ctxGorod     = "город"
	ctxDom       = "дом"
)

// Full-name stop words that also appear as literals elsewhere in the codebase,
// so they are defined once and reused to keep goconst clean.
const (
	stopWordGrazhdanin = "гражданин"
	stopWordGrazhdanka = "гражданка"
	stopWordRespublika = "республика"
	stopWordPo         = "по"
)

// Subject-marker literals shared across the name-context lists and the
// famous-person suppression, defined once to keep goconst clean.
const (
	ctxZayavitel = "заявитель"
	ctxImya      = "имя"
	ctxDlya      = "для"
	ctxNaImya    = "на имя"
	ctxFIOAbbrev = "ф.и.о."
	ctxPasport   = "паспорт"
)

type namesDetector struct {
	dict *namesDict
}

// NewNamesDetector builds the full_name detector.
func NewNamesDetector() pii.Detector {
	return &namesDetector{dict: loadNamesDict()}
}

func (d *namesDetector) Name() string { return "names" }

func (d *namesDetector) Categories() []pii.Category {
	return []pii.Category{pii.CatFullName}
}

func (d *namesDetector) Detect(text string) []pii.Span {
	return d.DetectLower(pii.Text{Raw: text, Lower: strings.ToLower(text)})
}

func (d *namesDetector) DetectLower(t pii.Text) []pii.Span {
	text := t.Raw
	toks := tokenize(text)
	nt := make([]nameToken, len(toks))
	for i, tok := range toks {
		nt[i].token = tok
		nt[i].lower = tokenLower(t, tok)
		nt[i].isName, nt[i].isSurname, nt[i].isSurnameGuess, nt[i].isPatr, nt[i].isInitial, nt[i].isPatrMarker =
			d.classify(nt[i].lower)
	}

	var cands []int
	for i := range nt {
		t := &nt[i]
		if t.isNameLike() {
			cands = append(cands, i)
		}
	}

	covered := make([]bool, len(nt))
	var spans []pii.Span
	i := 0
	for i < len(cands) {
		i += d.processCandidate(text, nt, cands, i, t, covered, &spans)
	}
	spans = append(spans, d.detectLatinNames(t, toks, covered)...)
	spans = append(spans, d.detectForeignNames(t, nt, covered)...)
	return spans
}

// processCandidate tries to emit a span starting at candidate index i. It
// returns the number of candidate indices to advance.
func (d *namesDetector) processCandidate(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) int {
	ci := cands[i]
	if covered[ci] {
		return 1
	}
	if handled, adv := d.turkicPatronymic(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.threeTokenName(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.twoTokenName(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.surnameGapName(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.patrSurnameName(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.surnameUnknownName(text, nt, cands, i, t, covered, spans); handled {
		return adv
	}
	if handled, adv := d.singleNameWithContext(nt, cands, i, t, covered, spans); handled {
		return adv
	}
	return 1
}

// singleNameWithContext emits a single given name when a name context keyword
// appears to the left.
func (d *namesDetector) singleNameWithContext(
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	tok := nt[cands[i]]
	if !tok.isName || !hasLeftContext(t, tok.start, nameContext, 30) {
		return false, 0
	}
	*spans = append(
		*spans,
		pii.Span{Start: tok.start, End: tok.end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.8},
	)
	covered[cands[i]] = true
	return true, 1
}

// turkicPatronymic handles a 4-token Turkic patronymic: surname + name + name +
// кызы/оглы/улы. It returns whether it handled the case and how many candidate
// indices to advance.
func (d *namesDetector) turkicPatronymic(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if i+1 >= len(cands) || !isSurnamePatrMarkerPair(nt, cands, i) {
		return false, 0
	}
	mid1, mid2, ok := twoNameGap(nt, cands[i], cands[i+1])
	if !ok {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[mid1], nt[mid2], nt[cands[i+1]]}
	if d.isFamous(t, seq) {
		return false, 0
	}
	*spans = append(
		*spans,
		pii.Span{Start: seq[0].start, End: seq[3].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.95},
	)
	covered[cands[i]] = true
	covered[mid1] = true
	covered[mid2] = true
	covered[cands[i+1]] = true
	return true, 2
}

// threeTokenName handles a three-token name sequence, optionally extending the
// span to a maiden surname in parentheses.
func (d *namesDetector) threeTokenName(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if !threeWhitespaceSeparated(text, nt, cands, i) {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[cands[i+1]], nt[cands[i+2]]}
	ok, conf := d.validSeq(seq, t)
	if !ok {
		return false, 0
	}
	start := seq[0].start
	if extStart, ok := maidenSurnameStart(text, nt, cands, i, nt[cands[i+1]].start, start); ok {
		start = extStart
		covered[cands[i-1]] = true
	}
	*spans = append(
		*spans,
		pii.Span{Start: start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf},
	)
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	covered[cands[i+2]] = true
	return true, 3
}

// twoTokenName handles a two-token name sequence.
func (d *namesDetector) twoTokenName(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if i+1 >= len(cands) || !onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[cands[i+1]]}
	ok, conf := d.validSeq(seq, t)
	if !ok {
		return false, 0
	}
	*spans = append(
		*spans,
		pii.Span{Start: seq[0].start, End: seq[1].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf},
	)
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	return true, 2
}

// threeWhitespaceSeparated reports whether the three candidate tokens at
// cands[i], cands[i+1] and cands[i+2] exist and are separated only by
// whitespace.
func threeWhitespaceSeparated(text string, nt []nameToken, cands []int, i int) bool {
	if i+2 >= len(cands) {
		return false
	}
	if !onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) {
		return false
	}
	return onlyWhitespace(text, nt[cands[i+1]].end, nt[cands[i+2]].start)
}

// maidenSurnameStart returns the start of a maiden surname in parentheses that
// precedes the sequence at cands[i], and whether the preceding surname token
// should be marked covered. When no maiden surname is present it returns
// seqStart and false.
func maidenSurnameStart(text string, nt []nameToken, cands []int, i int, endPos, seqStart int) (int, bool) {
	if i == 0 || !nt[cands[i-1]].isSurnameLike() {
		return seqStart, false
	}
	if !hasOpenParen(text, nt[cands[i-1]].end, nt[cands[i]].start) {
		return seqStart, false
	}
	if !hasCloseParen(text, nt[cands[i]].end, endPos) {
		return seqStart, false
	}
	return nt[cands[i-1]].start, true
}

// isSurnamePatrMarkerPair reports whether cands[i] is a surname-like token and
// cands[i+1] is a patronymic marker.
func isSurnamePatrMarkerPair(nt []nameToken, cands []int, i int) bool {
	return nt[cands[i]].isSurnameLike() && nt[cands[i+1]].isPatrMarker
}

// isSurnamePatrPair reports whether cands[i] is a surname-like token and
// cands[i+1] is a patronymic.
func isSurnamePatrPair(nt []nameToken, cands []int, i int) bool {
	return nt[cands[i]].isSurnameLike() && nt[cands[i+1]].isPatr
}

// isPatrSurnamePair reports whether cands[i] is a patronymic and cands[i+1] is
// a surname-like token.
func isPatrSurnamePair(nt []nameToken, cands []int, i int) bool {
	return nt[cands[i]].isPatr && nt[cands[i+1]].isSurnameLike()
}

// surnameGapName handles a surname + unknown given name + patronymic sequence,
// where the patronymic makes the sequence unambiguous even when the given name
// is not in the dictionary.
func (d *namesDetector) surnameGapName(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if i+1 >= len(cands) || !isSurnamePatrPair(nt, cands, i) {
		return false, 0
	}
	ctx := nameMatchCtx{text: text, nt: nt, cands: cands, t: t, covered: covered, spans: spans}
	if mid, ok := singleNameGap(nt, cands[i], cands[i+1]); ok {
		return d.emitGapName(ctx, i, mid, 0.95)
	}
	if mid, ok := lowercaseNameGap(nt, cands[i], cands[i+1], t); ok {
		return d.emitGapName(ctx, i, mid, 0.9)
	}
	return false, 0
}

// emitGapName emits a surname + given name + patronymic span for a gap name at
// mid, optionally extending to a maiden surname in parentheses.
func (d *namesDetector) emitGapName(ctx nameMatchCtx, i, mid int, conf float64) (bool, int) {
	nt, cands, covered, spans := ctx.nt, ctx.cands, ctx.covered, ctx.spans
	seq := []nameToken{nt[cands[i]], nt[mid], nt[cands[i+1]]}
	if d.isFamous(ctx.t, seq) {
		return false, 0
	}
	start := seq[0].start
	if extStart, ok := maidenSurnameStart(ctx.text, nt, cands, i, nt[mid].start, start); ok {
		start = extStart
		covered[cands[i-1]] = true
	}
	*spans = append(
		*spans,
		pii.Span{Start: start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf},
	)
	covered[cands[i]] = true
	covered[mid] = true
	covered[cands[i+1]] = true
	return true, 2
}

// patrSurnameName handles a name + patronymic + surname sequence where the given
// name is unknown but capitalised.
func (d *namesDetector) patrSurnameName(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if i+1 >= len(cands) || !isPatrSurnamePair(nt, cands, i) {
		return false, 0
	}
	mid, ok := unknownNameBefore(nt, cands[i])
	if !ok {
		return false, 0
	}
	seq := []nameToken{nt[mid], nt[cands[i]], nt[cands[i+1]]}
	if d.isFamous(t, seq) {
		return false, 0
	}
	*spans = append(
		*spans,
		pii.Span{Start: seq[0].start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9},
	)
	covered[mid] = true
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	return true, 2
}

// surnameUnknownName handles a surname + unknown given name sequence where the
// given name is not in the dictionary but a name context keyword (e.g. "зовут")
// appears to the left (e.g. "зовут Каримов Бахтиёр").
func (d *namesDetector) surnameUnknownName(
	text string,
	nt []nameToken,
	cands []int,
	i int,
	t pii.Text,
	covered []bool,
	spans *[]pii.Span,
) (bool, int) {
	if !nt[cands[i]].isSurnameLike() {
		return false, 0
	}
	ci := cands[i]
	if ci+1 >= len(nt) {
		return false, 0
	}
	next := nt[ci+1]
	if next.isNameLike() || stopWords[next.lower] {
		return false, 0
	}
	if !onlyWhitespace(text, nt[ci].end, next.start) {
		return false, 0
	}
	r, _ := utf8.DecodeRuneInString(next.text)
	if !isUpperRune(r) {
		return false, 0
	}
	if !hasLeftContext(t, nt[ci].start, nameContext, 30) {
		return false, 0
	}
	seq := []nameToken{nt[ci], next}
	if d.isFamous(t, seq) {
		return false, 0
	}
	*spans = append(
		*spans,
		pii.Span{Start: seq[0].start, End: seq[1].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9},
	)
	covered[ci] = true
	covered[ci+1] = true
	return true, 1
}

func (d *namesDetector) validSeq(seq []nameToken, t pii.Text) (bool, float64) {
	if d.isFamous(t, seq) {
		return false, 0
	}
	n := len(seq)
	if n == 3 {
		return d.validSeq3(seq, t)
	}
	if n == 2 {
		return d.validSeq2(seq, t)
	}
	return false, 0
}

// validSeq3 validates a three-token name sequence.
func (d *namesDetector) validSeq3(seq []nameToken, t pii.Text) (bool, float64) {
	if ok, conf := d.seq3SurnameNamePatr(seq); ok {
		return ok, conf
	}
	if ok, conf := d.seq3NamePatrSurname(seq); ok {
		return ok, conf
	}
	if ok, conf := d.seq3SurnameInitials(seq); ok {
		return ok, conf
	}
	if ok, conf := d.seq3NameInitials(seq); ok {
		return ok, conf
	}
	if ok, conf := d.seq3InitialsSurname(seq); ok {
		return ok, conf
	}
	return false, 0
}

func (d *namesDetector) seq3SurnameNamePatr(seq []nameToken) (bool, float64) {
	if seq[0].isSurnameLike() && seq[1].isName && seq[2].isPatr {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3NamePatrSurname(seq []nameToken) (bool, float64) {
	if seq[0].isName && seq[1].isPatr && seq[2].isSurnameLike() {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3SurnameInitials(seq []nameToken) (bool, float64) {
	if seq[0].isSurnameLike() && seq[1].isInitial && seq[2].isInitial {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3NameInitials(seq []nameToken) (bool, float64) {
	if seq[0].isName && seq[1].isInitial && seq[2].isInitial {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3InitialsSurname(seq []nameToken) (bool, float64) {
	if seq[0].isInitial && seq[1].isInitial && seq[2].isSurnameLike() {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

// validSeq2 validates a two-token name sequence.
func (d *namesDetector) validSeq2(seq []nameToken, t pii.Text) (bool, float64) {
	if d.seq2NameSurname(seq) || d.seq2SurnameName(seq) {
		return true, 0.85
	}
	if d.seq2NamePatr(seq, t) {
		return true, 0.85
	}
	return false, 0
}

// seq2NameSurname reports whether the sequence is "name surname".
func (d *namesDetector) seq2NameSurname(seq []nameToken) bool {
	return seq[0].isName && seq[1].isSurnameLike() && d.hasDictOrPatr(seq)
}

// seq2SurnameName reports whether the sequence is "surname name".
func (d *namesDetector) seq2SurnameName(seq []nameToken) bool {
	return seq[0].isSurnameLike() && seq[1].isName && d.hasDictOrPatr(seq)
}

// seq2NamePatr reports whether the sequence is "name patronymic" with a name
// context keyword to the left, or a name+patronymic signature at the end of the
// text (e.g. "Роза Мусаевна."). A famous person's name+patronymic (e.g. "Фёдор
// Михайлович") is not PII.
func (d *namesDetector) seq2NamePatr(seq []nameToken, t pii.Text) bool {
	if !seq[0].isName || !seq[1].isPatr || !d.hasDictOrPatr(seq) {
		return false
	}
	if hasLeftContext(t, seq[0].start, nameContext, 30) {
		return true
	}
	if !endsPhrase(t.Raw, seq[1].end) {
		return false
	}
	return !famousPatronymics[normalizeWord(seq[0].lower)+" "+normalizeWord(seq[1].lower)]
}

func (d *namesDetector) hasDictOrPatr(seq []nameToken) bool {
	for _, t := range seq {
		if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr {
			return true
		}
	}
	return false
}

func (d *namesDetector) isFamous(t pii.Text, seq []nameToken) bool {
	var stems []string
	for _, tok := range seq {
		// Ignore patronymics and initials: famous persons are matched on
		// name + surname only.
		if tok.isPatr || tok.isInitial {
			continue
		}
		stems = append(stems, normalizeWord(tok.lower))
	}
	famous := false
	for _, f := range d.dict.famous {
		if sameMultiset(stems, f) {
			famous = true
			break
		}
	}
	if !famous {
		return false
	}
	// Suppression by famous.txt is not applied when a subject marker appears
	// within 30 runes to the left (e.g. "клиент Лев Толстой") or when another
	// PII span is present in the same line (e.g. a phone or birth date next to
	// the name). In those cases the famous person's name is the client's own
	// name and must be masked.
	if hasLeftContext(t, seq[0].start, famousSubjectMarkers, 30) {
		return false
	}
	if famousOtherPIISameLine(t, seq[0].start, seq[len(seq)-1].end) {
		return false
	}
	return true
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int)
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
		if m[x] < 0 {
			return false
		}
	}
	return true
}

// famousOtherPIIRe matches the other personal-data spans that, when present in
// the same line as a famous person's name, disable the famous-person
// suppression: phone, passport, birth date, email, snils and inn. Card numbers
// are checked separately with a Luhn validation (see containsLuhnCard) because
// a bare digit-run pattern would also match ISBNs and other non-card numbers.
var famousOtherPIIRe = regexp.MustCompile(
	`(?i)(?:\+7|8|7)[\s(-]*\d{3,4}[\s)-]*\d{2,3}[\s-]*\d{2}[\s-]*\d{2}|` +
		`\b\d{4}\s+\d{6}\b|` +
		`\b\d{1,2}[./-]\d{1,2}[./-]\d{4}\b|` +
		`[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.\p{L}{2,}|` +
		`\b\d{3}[\s-]\d{3}[\s-]\d{3}[\s-]\d{2}\b|` +
		`\b\d{12}\b`,
)

// famousOtherPIISameLine reports whether another PII span (phone, passport,
// birth date, email, snils, inn or card number) appears in the same line as the
// name sequence [start,end). The name sequence itself is excluded so its own
// tokens do not count as the other PII.
func famousOtherPIISameLine(t pii.Text, start, end int) bool {
	lineStart := start
	for lineStart > 0 && t.Raw[lineStart-1] != '\n' {
		lineStart--
	}
	lineEnd := end
	for lineEnd < len(t.Raw) && t.Raw[lineEnd] != '\n' {
		lineEnd++
	}
	line := t.Raw[lineStart:lineEnd]
	// Exclude the name sequence itself from the search.
	before := line[:start-lineStart]
	after := line[end-lineStart:]
	return famousOtherPIIRe.MatchString(before) || famousOtherPIIRe.MatchString(after) ||
		containsLuhnCard(before) || containsLuhnCard(after)
}

// containsLuhnCard reports whether s contains a Luhn-valid card number: a run
// of 13-19 digits (with optional spaces or dashes between groups).
func containsLuhnCard(s string) bool {
	digits := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits += string(c)
			continue
		}
		if c == ' ' || c == '-' {
			continue
		}
		digits = ""
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnValid(digits)
}

// luhnValid reports whether the digit string passes the Luhn checksum.
func luhnValid(d string) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// hasLeftContext reports whether any keyword appears within the last window
// runes before pos. Keywords must already be lowercased.
func hasLeftContext(t pii.Text, pos int, keywords []string, window int) bool {
	prefix := runeWindowBefore(t, pos, window)
	for _, kw := range keywords {
		if strings.Contains(prefix, kw) {
			return true
		}
	}
	return false
}

// hasRightContext reports whether any keyword appears within the first window
// runes after pos. Keywords must already be lowercased.
func hasRightContext(t pii.Text, pos int, keywords []string, window int) bool {
	suffix := runeWindowAfter(t, pos, window)
	for _, kw := range keywords {
		if strings.Contains(suffix, kw) {
			return true
		}
	}
	return false
}

// singleNameGap reports whether there is exactly one non-candidate token
// between candidate indices a and b, and that token looks like a given name
// (capitalised, not a stopword). It returns the token index and true when so.
func singleNameGap(nt []nameToken, a, b int) (int, bool) {
	if b-a != 2 {
		return 0, false
	}
	mid := a + 1
	t := nt[mid]
	if t.isNameLikeNoMarker() {
		return 0, false
	}
	if stopWords[t.lower] {
		return 0, false
	}
	r, _ := utf8.DecodeRuneInString(t.text)
	if !isUpperRune(r) {
		return 0, false
	}
	return mid, true
}

// twoNameGap reports whether there are exactly two non-candidate tokens between
// candidate indices a and b, both looking like given names (capitalised, not
// stopwords). It returns the two token indices and true when so. This supports
// Turkic patronymics of the form "name1 name2 кызы/оглы/улы".
func twoNameGap(nt []nameToken, a, b int) (int, int, bool) {
	if b-a != 3 {
		return 0, 0, false
	}
	mid1, mid2 := a+1, a+2
	for _, mid := range []int{mid1, mid2} {
		t := nt[mid]
		if t.isNameLike() {
			return 0, 0, false
		}
		if stopWords[t.lower] {
			return 0, 0, false
		}
		r, _ := utf8.DecodeRuneInString(t.text)
		if !isUpperRune(r) {
			return 0, 0, false
		}
	}
	return mid1, mid2, true
}

// lowercaseNameGap reports whether there is exactly one non-candidate token
// between candidate indices a and b that looks like a given name but is not
// capitalised. It is accepted only when a name context keyword appears within
// 40 runes to the left (e.g. "клиент: ахметзянова зульфия ильгизовна") or the
// sequence occupies the whole line.
func lowercaseNameGap(nt []nameToken, a, b int, t pii.Text) (int, bool) {
	if b-a != 2 {
		return 0, false
	}
	mid := a + 1
	tok := nt[mid]
	if tok.isNameLike() {
		return 0, false
	}
	if stopWords[tok.lower] {
		return 0, false
	}
	if !hasLeftContext(t, tok.start, lowercaseNameContext, 40) && !occupiesWholeLine(t.Raw, nt[a].start, nt[b].end) {
		return 0, false
	}
	return mid, true
}

// unknownNameBefore reports whether the token immediately before candidate
// index b is a capitalised word that is not a candidate (an unknown given name)
// and not a stopword. It returns the token index and true when so.
func unknownNameBefore(nt []nameToken, b int) (int, bool) {
	if b == 0 {
		return 0, false
	}
	mid := b - 1
	t := nt[mid]
	if t.isNameLike() {
		return 0, false
	}
	if stopWords[t.lower] {
		return 0, false
	}
	r, _ := utf8.DecodeRuneInString(t.text)
	if !isUpperRune(r) {
		return 0, false
	}
	return mid, true
}

// occupiesWholeLine reports whether the byte range [a,b) spans from the start
// of a line to the end of that line (ignoring surrounding whitespace).
func occupiesWholeLine(text string, a, b int) bool {
	// The sequence must start at the beginning of a line (or the whole text).
	lineStart := a
	for lineStart > 0 && text[lineStart-1] != '\n' {
		lineStart--
	}
	if !onlyWhitespace(text, lineStart, a) {
		return false
	}
	// The sequence must end at the end of a line (or the whole text).
	lineEnd := b
	for lineEnd < len(text) && text[lineEnd] != '\n' {
		lineEnd++
	}
	return onlyWhitespace(text, b, lineEnd)
}
