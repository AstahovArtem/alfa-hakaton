package detectors

import (
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
func (d *namesDetector) processCandidate(text string, nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) int {
	ci := cands[i]
	if covered[ci] {
		return 1
	}
	if handled, adv := d.turkicPatronymic(text, nt, cands, i, covered, spans); handled {
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
	if handled, adv := d.singleNameWithContext(nt, cands, i, t, covered, spans); handled {
		return adv
	}
	return 1
}

// singleNameWithContext emits a single given name when a name context keyword
// appears to the left.
func (d *namesDetector) singleNameWithContext(nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) (bool, int) {
	tok := nt[cands[i]]
	if !tok.isName || !hasLeftContext(t, tok.start, nameContext, 30) {
		return false, 0
	}
	*spans = append(*spans, pii.Span{Start: tok.start, End: tok.end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.8})
	covered[cands[i]] = true
	return true, 1
}

// turkicPatronymic handles a 4-token Turkic patronymic: surname + name + name +
// кызы/оглы/улы. It returns whether it handled the case and how many candidate
// indices to advance.
func (d *namesDetector) turkicPatronymic(text string, nt []nameToken, cands []int, i int, covered []bool, spans *[]pii.Span) (bool, int) {
	if i+1 >= len(cands) || !(nt[cands[i]].isSurname || nt[cands[i]].isSurnameGuess) || !nt[cands[i+1]].isPatrMarker {
		return false, 0
	}
	mid1, mid2, ok := twoNameGap(nt, cands[i], cands[i+1])
	if !ok {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[mid1], nt[mid2], nt[cands[i+1]]}
	if d.isFamous(seq) {
		return false, 0
	}
	*spans = append(*spans, pii.Span{Start: seq[0].start, End: seq[3].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.95})
	covered[cands[i]] = true
	covered[mid1] = true
	covered[mid2] = true
	covered[cands[i+1]] = true
	return true, 2
}

// threeTokenName handles a three-token name sequence, optionally extending the
// span to a maiden surname in parentheses.
func (d *namesDetector) threeTokenName(text string, nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) (bool, int) {
	if i+2 >= len(cands) ||
		!onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) ||
		!onlyWhitespace(text, nt[cands[i+1]].end, nt[cands[i+2]].start) {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[cands[i+1]], nt[cands[i+2]]}
	ok, conf := d.validSeq(seq, t)
	if !ok {
		return false, 0
	}
	start := seq[0].start
	if i > 0 && (nt[cands[i-1]].isSurname || nt[cands[i-1]].isSurnameGuess) &&
		hasOpenParen(text, nt[cands[i-1]].end, nt[cands[i]].start) &&
		hasCloseParen(text, nt[cands[i]].end, nt[cands[i+1]].start) {
		start = nt[cands[i-1]].start
		covered[cands[i-1]] = true
	}
	*spans = append(*spans, pii.Span{Start: start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf})
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	covered[cands[i+2]] = true
	return true, 3
}

// twoTokenName handles a two-token name sequence.
func (d *namesDetector) twoTokenName(text string, nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) (bool, int) {
	if i+1 >= len(cands) || !onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) {
		return false, 0
	}
	seq := []nameToken{nt[cands[i]], nt[cands[i+1]]}
	ok, conf := d.validSeq(seq, t)
	if !ok {
		return false, 0
	}
	*spans = append(*spans, pii.Span{Start: seq[0].start, End: seq[1].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf})
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	return true, 2
}

// surnameGapName handles a surname + unknown given name + patronymic sequence,
// where the patronymic makes the sequence unambiguous even when the given name
// is not in the dictionary.
func (d *namesDetector) surnameGapName(text string, nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) (bool, int) {
	if i+1 >= len(cands) || !(nt[cands[i]].isSurname || nt[cands[i]].isSurnameGuess) || !nt[cands[i+1]].isPatr {
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
	if d.isFamous(seq) {
		return false, 0
	}
	start := seq[0].start
	if i > 0 && (nt[cands[i-1]].isSurname || nt[cands[i-1]].isSurnameGuess) &&
		hasOpenParen(ctx.text, nt[cands[i-1]].end, nt[cands[i]].start) &&
		hasCloseParen(ctx.text, nt[cands[i]].end, nt[mid].start) {
		start = nt[cands[i-1]].start
		covered[cands[i-1]] = true
	}
	*spans = append(*spans, pii.Span{Start: start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf})
	covered[cands[i]] = true
	covered[mid] = true
	covered[cands[i+1]] = true
	return true, 2
}

// patrSurnameName handles a name + patronymic + surname sequence where the given
// name is unknown but capitalised.
func (d *namesDetector) patrSurnameName(text string, nt []nameToken, cands []int, i int, t pii.Text, covered []bool, spans *[]pii.Span) (bool, int) {
	if i+1 >= len(cands) || !nt[cands[i]].isPatr || !(nt[cands[i+1]].isSurname || nt[cands[i+1]].isSurnameGuess) {
		return false, 0
	}
	mid, ok := unknownNameBefore(nt, cands[i])
	if !ok {
		return false, 0
	}
	seq := []nameToken{nt[mid], nt[cands[i]], nt[cands[i+1]]}
	if d.isFamous(seq) {
		return false, 0
	}
	*spans = append(*spans, pii.Span{Start: seq[0].start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9})
	covered[mid] = true
	covered[cands[i]] = true
	covered[cands[i+1]] = true
	return true, 2
}

func (d *namesDetector) validSeq(seq []nameToken, t pii.Text) (bool, float64) {
	if d.isFamous(seq) {
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
	if (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isName && seq[2].isPatr {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3NamePatrSurname(seq []nameToken) (bool, float64) {
	if seq[0].isName && seq[1].isPatr && (seq[2].isSurname || seq[2].isSurnameGuess) {
		if d.hasDictOrPatr(seq) {
			return true, 0.95
		}
	}
	return false, 0
}

func (d *namesDetector) seq3SurnameInitials(seq []nameToken) (bool, float64) {
	if (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isInitial && seq[2].isInitial {
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
	if seq[0].isInitial && seq[1].isInitial && (seq[2].isSurname || seq[2].isSurnameGuess) {
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
	return seq[0].isName && (seq[1].isSurname || seq[1].isSurnameGuess) && d.hasDictOrPatr(seq)
}

// seq2SurnameName reports whether the sequence is "surname name".
func (d *namesDetector) seq2SurnameName(seq []nameToken) bool {
	return (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isName && d.hasDictOrPatr(seq)
}

// seq2NamePatr reports whether the sequence is "name patronymic" with a name
// context keyword to the left.
func (d *namesDetector) seq2NamePatr(seq []nameToken, t pii.Text) bool {
	return seq[0].isName && seq[1].isPatr && d.hasDictOrPatr(seq) &&
		hasLeftContext(t, seq[0].start, nameContext, 30)
}

func (d *namesDetector) hasDictOrPatr(seq []nameToken) bool {
	for _, t := range seq {
		if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr {
			return true
		}
	}
	return false
}

func (d *namesDetector) isFamous(seq []nameToken) bool {
	var stems []string
	for _, t := range seq {
		// Ignore patronymics and initials: famous persons are matched on
		// name + surname only.
		if t.isPatr || t.isInitial {
			continue
		}
		stems = append(stems, normalizeWord(t.lower))
	}
	for _, f := range d.dict.famous {
		if sameMultiset(stems, f) {
			return true
		}
	}
	return false
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
