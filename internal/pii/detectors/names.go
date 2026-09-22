package detectors

import (
	"embed"
	"strings"
	"sync"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

//go:embed dict/*.txt
var namesFS embed.FS

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

// token is a single word (letters, optional inner hyphen) or an initial
// (single letter followed by a dot). Positions are byte offsets.
type token struct {
	start, end int
	text       string
}

// tokenize splits text into word/initial tokens.
func tokenize(text string) []token {
	var toks []token
	i := 0
	n := len(text)
	for i < n {
		r, size := utf8.DecodeRuneInString(text[i:])
		if !isLetterRune(r) {
			i += size
			continue
		}
		start := i
		runeCount := 0
		i, runeCount = consumeWord(text, i, runeCount)
		if runeCount == 1 && i < n && text[i] == '.' {
			i++
		}
		toks = append(toks, token{start: start, end: i, text: text[start:i]})
	}
	return toks
}

// consumeWord advances i past a run of letters and inner hyphens, returning the
// new position and the number of letters consumed.
func consumeWord(text string, i, runeCount int) (int, int) {
	n := len(text)
	for i < n {
		r, size := utf8.DecodeRuneInString(text[i:])
		if isLetterRune(r) {
			i += size
			runeCount++
			continue
		}
		if r == '-' && i+size < n {
			nr, _ := utf8.DecodeRuneInString(text[i+size:])
			if isLetterRune(nr) {
				i += size
				continue
			}
		}
		break
	}
	return i, runeCount
}

// tokenLower returns the lowercased form of a token. When the lowercased text
// has the same byte length as the raw text, the token is sliced directly from
// Text.Lower, avoiding a per-token strings.ToLower call.
func tokenLower(t pii.Text, tok token) string {
	if t.LowerOK() {
		return t.Lower[tok.start:tok.end]
	}
	return strings.ToLower(tok.text)
}

func isLatinLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// onlyWhitespace reports whether the byte range [a,b) contains only whitespace.
func onlyWhitespace(text string, a, b int) bool {
	return strings.TrimSpace(text[a:b]) == ""
}

// nameToken is a token annotated with its classification.
type nameToken struct {
	token
	lower          string
	isName         bool
	isSurname      bool
	isSurnameGuess bool
	isPatr         bool
	isInitial      bool
	isPatrMarker   bool
}

// nameMatchCtx bundles the shared state passed between name-matching helpers.
type nameMatchCtx struct {
	text    string
	nt      []nameToken
	cands   []int
	t       pii.Text
	covered []bool
	spans   *[]pii.Span
}

// namesDict holds the loaded dictionaries.
type namesDict struct {
	names        map[string]bool
	nameStems    map[string]bool
	surnameStems map[string]bool
	famous       [][]string
}

var (
	namesOnce sync.Once
	namesData *namesDict
)

func loadNamesDict() *namesDict {
	namesOnce.Do(func() {
		namesData = &namesDict{
			names:        make(map[string]bool),
			nameStems:    make(map[string]bool),
			surnameStems: make(map[string]bool),
		}
		for _, line := range readDict(dictFirstNames) {
			namesData.names[line] = true
			namesData.nameStems[nameStem(line)] = true
		}
		for _, line := range readDict(dictSurnames) {
			namesData.surnameStems[surnameStem(line)] = true
		}
		for _, line := range readDict("dict/famous.txt") {
			words := strings.Fields(line)
			var stems []string
			for _, w := range words {
				stems = append(stems, normalizeWord(w))
			}
			namesData.famous = append(namesData.famous, stems)
		}
	})
	return namesData
}

func readDict(path string) []string {
	data, err := namesFS.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// nameStem reduces a name to its stem: drop the last vowel if it ends in -а/-я/-й.
func nameStem(name string) string {
	r := []rune(name)
	if len(r) == 0 {
		return name
	}
	last := r[len(r)-1]
	if last == 'а' || last == 'я' || last == 'й' {
		return string(r[:len(r)-1])
	}
	return name
}

// surnameStem reduces a dict surname to its stem by removing the possessive suffix.
func surnameStem(s string) string {
	for _, suf := range []string{"ов", "ев", "ин", "ын"} {
		if strings.HasSuffix(s, suf) {
			return s[:len(s)-len(suf)]
		}
	}
	return s
}

// normalizeWord reduces a word to a matching stem for the famous-person check.
func normalizeWord(lower string) string {
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е"} {
		if strings.HasSuffix(lower, e) {
			lower = lower[:len(lower)-len(e)]
			break
		}
	}
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(lower, suf) {
			lower = lower[:len(lower)-len(suf)]
			break
		}
	}
	return lower
}

var stopWords = map[string]bool{
	"банк": true, "москва": true, ctxRussia: true, "российская": true, "федерация": true,
	ctxOblast: true, ctxGorod: true, "улица": true, ctxDom: true, ctxClient: true, "паспорт": true,
	ctxOtdelenie: true, "офис": true, "договор": true, "счёт": true, "карта": true, "номер": true,
	"январь": true, monthJanuary: true, "февраль": true, monthFebruary: true, "март": true,
	"апрель": true, monthApril: true, "май": true, monthMay: true, "июнь": true, monthJune: true,
	"июль": true, monthJuly: true, monthAugust: true, "сентябрь": true, monthSeptember: true,
	"октябрь": true, monthOctober: true, "ноябрь": true, monthNovember: true, "декабрь": true, monthDecember: true,
	"понедельник": true, "вторник": true, "среда": true, "четверг": true, "пятница": true,
	"суббота": true, "воскресенье": true,
}

var nameContext = []string{
	ctxClient, "заявитель", "гражданин", "гражданка", "держатель", "владелец",
	ctxFIO, "имя", ctxZovut, "меня зовут", "сотрудник", "менеджер",
}

// lowercaseNameContext are keywords that, when present to the left, allow a
// full name to be accepted even when its tokens are not capitalised (e.g.
// "клиент: ахметзянова зульфия ильгизовна").
var lowercaseNameContext = []string{
	ctxClient, ctxFIO, "ф.и.о.", "заёмщик", "заемщик", "имя", ctxZovut, "обращаться",
	"представьтесь", "фамилию", "фамилия",
}

// patrMarkers are Turkic patronymic markers that combine with the preceding
// given name to form a patronymic (e.g. "Фарид кызы", "Али оглы").
var patrMarkers = map[string]bool{
	"кызы": true, "оглы": true, "улы": true,
}

// latinNameContext are keywords that, when present to the left, allow a pair of
// Latin words with capital initials to be accepted as a full name (e.g.
// "my name is Tigran Avakyan", "name: Ivanov Ivan"). Without such context Latin
// words are left untouched.
var latinNameContext = []string{
	"my name is", "name:", "имя:", ctxClient, "заявитель", "фио:", "ф.и.о.",
}

// foreignNameContext are keywords that, when present to the left, allow a run of
// 2-4 capitalised words that are not in the Russian dictionaries to be accepted
// as a full name (e.g. a reply "Нгуен Тхи Хоа" after "Как к вам обращаться?",
// or "ЛИ ЧЖИ ХУН" after "Данные для пропуска:").
var foreignNameContext = []string{
	"обращаться", ctxZovut, "фамилию", "фамилия", ctxFIO, "представьтесь", "пропуска",
}

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
		if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial || t.isPatrMarker {
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

// detectLatinNames finds runs of consecutive Latin words with capital initials
// that follow a name context keyword (e.g. "my name is Tigran Avakyan",
// "name: Ivanov Ivan", "Заявитель Nguyen Van Long"). Latin words are not in the
// Russian dictionaries, so they are handled separately and only when a context
// keyword is present.
func (d *namesDetector) detectLatinNames(t pii.Text, toks []token, covered []bool) []pii.Span {
	var spans []pii.Span
	i := 0
	for i < len(toks) {
		if covered[i] || !isLatinToken(toks[i]) {
			i++
			continue
		}
		j := i
		for j < len(toks) && isLatinToken(toks[j]) {
			j++
		}
		capIdx := collectCapitalized(toks, i, j, covered)
		spans = append(spans, d.emitLatinSpans(t, toks, capIdx, covered)...)
		i = j
	}
	return spans
}

// collectCapitalized returns the indices of the capitalized Latin words in the
// run [i,j) that are not already covered.
func collectCapitalized(toks []token, i, j int, covered []bool) []int {
	var capIdx []int
	for k := i; k < j; k++ {
		if covered[k] {
			continue
		}
		if isCapitalized(toks[k].text) {
			capIdx = append(capIdx, k)
		}
	}
	return capIdx
}

// emitLatinSpans emits spans for consecutive capitalized words (2 or 3) that
// follow a context keyword.
func (d *namesDetector) emitLatinSpans(t pii.Text, toks []token, capIdx []int, covered []bool) []pii.Span {
	text := t.Raw
	var spans []pii.Span
	for k := 0; k+1 < len(capIdx); k++ {
		a, b := capIdx[k], capIdx[k+1]
		if !onlyWhitespace(text, toks[a].end, toks[b].start) {
			continue
		}
		if !hasLeftContext(t, toks[a].start, latinNameContext, 40) {
			continue
		}
		end := toks[b].end
		covered[a] = true
		covered[b] = true
		if k+2 < len(capIdx) && onlyWhitespace(text, toks[b].end, toks[capIdx[k+2]].start) {
			end = toks[capIdx[k+2]].end
			covered[capIdx[k+2]] = true
			k++
		}
		spans = append(spans, pii.Span{Start: toks[a].start, End: end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9})
	}
	return spans
}

// isLatinToken reports whether every letter in the token is a Latin letter.
func isLatinToken(tok token) bool {
	for _, r := range tok.text {
		if !isLatinLetter(r) {
			return false
		}
	}
	return true
}

// isCapitalized reports whether the token starts with an uppercase letter.
func isCapitalized(text string) bool {
	r, _ := utf8.DecodeRuneInString(text)
	return isUpperRune(r)
}

// detectForeignNames finds runs of 2-4 capitalised words that are not in the
// Russian dictionaries and follow a foreign-name context keyword, where the run
// occupies the rest of its line (e.g. "Нгуен Тхи Хоа" after "Как к вам
// обращаться?", "ЛИ ЧЖИ ХУН" after "Данные для пропуска:").
func (d *namesDetector) detectForeignNames(t pii.Text, nt []nameToken, covered []bool) []pii.Span {
	text := t.Raw
	var spans []pii.Span
	i := 0
	for i < len(nt) {
		if covered[i] || !isForeignNameCandidate(nt[i]) {
			i++
			continue
		}
		j := i
		for j+1 < len(nt) && !covered[j+1] && isForeignNameCandidate(nt[j+1]) &&
			onlyWhitespace(text, nt[j].end, nt[j+1].start) &&
			!strings.Contains(text[nt[j].end:nt[j+1].start], "\n") {
			j++
		}
		runLen := j - i + 1
		if runLen >= 2 && runLen <= 4 &&
			hasLeftContext(t, nt[i].start, foreignNameContext, 40) &&
			endsPhrase(text, nt[j].end) {
			spans = append(spans, pii.Span{Start: nt[i].start, End: nt[j].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9})
			for k := i; k <= j; k++ {
				covered[k] = true
			}
			i = j + 1
			continue
		}
		i++
	}
	return spans
}

// isForeignNameCandidate reports whether a token could be part of a foreign
// full name: capitalised, not a known Russian name/surname/patronymic, not a
// stopword.
func isForeignNameCandidate(t nameToken) bool {
	if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial || t.isPatrMarker {
		return false
	}
	if stopWords[t.lower] {
		return false
	}
	if utf8.RuneCountInString(t.text) < 2 {
		return false
	}
	r, _ := utf8.DecodeRuneInString(t.text)
	return isUpperRune(r)
}

// endsPhrase reports whether the byte position b is followed by the end of the
// text, a newline, or a non-letter character (comma, period, etc.), i.e. the
// preceding run ends a phrase.
func endsPhrase(text string, b int) bool {
	i := b
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	if i >= len(text) || text[i] == '\n' {
		return true
	}
	r, _ := utf8.DecodeRuneInString(text[i:])
	return !isLetterRune(r)
}

// hasOpenParen reports whether the byte range [a,b) contains an opening
// parenthesis.
func hasOpenParen(text string, a, b int) bool {
	return strings.Contains(text[a:b], "(")
}

// hasCloseParen reports whether the byte range [a,b) contains a closing
// parenthesis.
func hasCloseParen(text string, a, b int) bool {
	return strings.Contains(text[a:b], ")")
}

func (d *namesDetector) classify(lower string) (isName, isSurname, isSurnameGuess, isPatr, isInitial, isPatrMarker bool) {
	if stopWords[lower] {
		return
	}
	isName = d.isNameToken(lower)
	isSurname, isSurnameGuess = d.isSurnameToken(lower)
	isPatr = isPatronymic(lower)
	isInitial = isInitialToken(lower)
	isPatrMarker = patrMarkers[lower]
	return
}

func (d *namesDetector) isNameToken(lower string) bool {
	if d.dict.names[lower] {
		return true
	}
	for _, e := range []string{"а", "я", "у", "ю", "ой", "ей", "ом", "ем", "е", "и", "ы"} {
		if strings.HasSuffix(lower, e) {
			stem := lower[:len(lower)-len(e)]
			if d.dict.names[stem] || d.dict.nameStems[stem] {
				return true
			}
		}
	}
	return false
}

func (d *namesDetector) isSurnameToken(lower string) (bool, bool) {
	return d.dictSurname(lower), suffixSurname(lower)
}

func (d *namesDetector) dictSurname(lower string) bool {
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е", "ов", "ев", "ин", "ын"} {
		if strings.HasSuffix(lower, e) {
			if d.dictSurnameBase(lower[:len(lower)-len(e)]) {
				return true
			}
		}
	}
	return d.dictSurnameBase(lower)
}

func (d *namesDetector) dictSurnameBase(s string) bool {
	for _, suf := range []string{"ов", "ев", "ин", "ын"} {
		if strings.HasSuffix(s, suf) {
			if d.dict.surnameStems[s[:len(s)-len(suf)]] {
				return true
			}
		}
	}
	return false
}

func suffixSurname(lower string) bool {
	for _, suf := range []string{sufSky, "цкий", sufSkaya, sufTskaya, "енко", "ук", "юк", "ян", "дзе", "швили", "ых", "их", sufOva, sufEva, sufYova, sufIna, sufYna, "ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е"} {
		if strings.HasSuffix(lower, e) {
			base := lower[:len(lower)-len(e)]
			for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын", sufSky, "цкий", sufSkaya, sufTskaya} {
				if strings.HasSuffix(base, suf) {
					return true
				}
			}
		}
	}
	return false
}

// patSuffixes are the base patronymic suffixes in the nominative case.
var patSuffixes = []string{"ович", "евич", "ич", sufOvna, sufEvna, sufIchna, sufInichna}

// patForms holds every inflected form of every patronymic suffix, so that
// patronymics in any case (e.g. "Сергеевны", "Маратовичу") are recognised.
var patForms = buildPatForms()

func buildPatForms() map[string]bool {
	forms := make(map[string]bool)
	for _, suf := range patSuffixes {
		forms[suf] = true
		if strings.HasSuffix(suf, "а") {
			// Feminine suffixes drop the final -а and take a case ending.
			r := []rune(suf)
			base := string(r[:len(r)-1])
			for _, e := range []string{"ы", "е", "у", "ой", "ою", "ам", sufAmi, "ах"} {
				forms[base+e] = true
			}
		} else {
			// Masculine suffixes append a case ending.
			for _, e := range []string{"а", "у", "ы", "е", "ем", "ом", "и", "ей", "ам", sufAmi, "ах"} {
				forms[suf+e] = true
			}
		}
	}
	return forms
}

func isPatronymic(lower string) bool {
	for suf := range patForms {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func isInitialToken(lower string) bool {
	r := []rune(lower)
	if len(r) != 2 || r[1] != '.' {
		return false
	}
	return isLetterRune(r[0])
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
	if seq[0].isName && (seq[1].isSurname || seq[1].isSurnameGuess) {
		if d.hasDictOrPatr(seq) {
			return true, 0.85
		}
	}
	if (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isName {
		if d.hasDictOrPatr(seq) {
			return true, 0.85
		}
	}
	if seq[0].isName && seq[1].isPatr {
		if d.hasDictOrPatr(seq) && hasLeftContext(t, seq[0].start, nameContext, 30) {
			return true, 0.85
		}
	}
	return false, 0
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
	if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial {
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
		if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial || t.isPatrMarker {
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
	if tok.isName || tok.isSurname || tok.isSurnameGuess || tok.isPatr || tok.isInitial || tok.isPatrMarker {
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
	if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial || t.isPatrMarker {
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
