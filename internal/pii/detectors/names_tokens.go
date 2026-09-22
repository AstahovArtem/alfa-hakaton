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

// isNameLike reports whether the token is any kind of name token (given name,
// surname, patronymic, initial or patronymic marker).
func (t nameToken) isNameLike() bool {
	return t.isCoreName() || t.isPatrMarker
}

// isNameLikeNoMarker reports whether the token is a name token other than a
// patronymic marker.
func (t nameToken) isNameLikeNoMarker() bool {
	return t.isCoreName()
}

// isCoreName reports whether the token is a given name, surname or patronymic.
func (t nameToken) isCoreName() bool {
	return t.isNameOrSurname() || t.isPatr || t.isInitial
}

// isNameOrSurname reports whether the token is a given name or a surname.
func (t nameToken) isNameOrSurname() bool {
	return t.isName || t.isSurname || t.isSurnameGuess
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
	for _, suf := range []string{sufOv, sufEv, sufIn, sufYn} {
		if strings.HasSuffix(s, suf) {
			return s[:len(s)-len(suf)]
		}
	}
	return s
}

// normalizeWord reduces a word to a matching stem for the famous-person check.
func normalizeWord(lower string) string {
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, sufAh, sufYm, sufIm, sufOy, sufOm, sufEm, "а", "у", "ы", "е"} {
		if strings.HasSuffix(lower, e) {
			lower = lower[:len(lower)-len(e)]
			break
		}
	}
	for _, suf := range []string{sufOv, sufEv, sufYov, sufIn, sufYn} {
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
	for _, e := range []string{"а", "я", "у", "ю", sufOy, sufEy, sufOm, sufEm, "е", "и", "ы"} {
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
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, sufAh, sufYm, sufIm, sufOy, sufOm, sufEm, "а", "у", "ы", "е", sufOv, sufEv, sufIn, sufYn} {
		if strings.HasSuffix(lower, e) {
			if d.dictSurnameBase(lower[:len(lower)-len(e)]) {
				return true
			}
		}
	}
	return d.dictSurnameBase(lower)
}

func (d *namesDetector) dictSurnameBase(s string) bool {
	for _, suf := range []string{sufOv, sufEv, sufIn, sufYn} {
		if strings.HasSuffix(s, suf) {
			if d.dict.surnameStems[s[:len(s)-len(suf)]] {
				return true
			}
		}
	}
	return false
}

func suffixSurname(lower string) bool {
	for _, suf := range []string{sufSky, "цкий", sufSkaya, sufTskaya, "енко", "ук", "юк", "ян", "дзе", "швили", "ых", "их", sufOva, sufEva, sufYova, sufIna, sufYna, sufOv, sufEv, sufYov, sufIn, sufYn} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	for _, e := range []string{sufYmi, sufImi, sufOgo, sufOmu, sufAmi, sufAh, sufYm, sufIm, sufOy, sufOm, sufEm, "а", "у", "ы", "е"} {
		if strings.HasSuffix(lower, e) && suffixSurnameBase(lower[:len(lower)-len(e)]) {
			return true
		}
	}
	return false
}

// suffixSurnameBase reports whether base ends with a surname suffix that, when
// combined with a case ending, forms an inflected surname.
func suffixSurnameBase(base string) bool {
	for _, suf := range []string{sufOv, sufEv, sufYov, sufIn, sufYn, sufSky, "цкий", sufSkaya, sufTskaya} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

// patSuffixes are the base patronymic suffixes in the nominative case.
var patSuffixes = []string{"ович", "евич", sufIch, sufOvna, sufEvna, sufIchna, sufInichna}

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
			for _, e := range []string{"ы", "е", "у", sufOy, "ою", "ам", sufAmi, sufAh} {
				forms[base+e] = true
			}
		} else {
			// Masculine suffixes append a case ending.
			for _, e := range []string{"а", "у", "ы", "е", sufEm, sufOm, "и", sufEy, "ам", sufAmi, sufAh} {
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
