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
		for i < n {
			r, size = utf8.DecodeRuneInString(text[i:])
			if isLetterRune(r) {
				i += size
				runeCount++
				continue
			}
			if r == '-' {
				if i+size < n {
					nr, _ := utf8.DecodeRuneInString(text[i+size:])
					if isLetterRune(nr) {
						i += size
						continue
					}
				}
				break
			}
			break
		}
		if runeCount == 1 && i < n && text[i] == '.' {
			i++
		}
		toks = append(toks, token{start: start, end: i, text: text[start:i]})
	}
	return toks
}

func isLetterRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
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
		for _, line := range readDict("dict/first_names.txt") {
			namesData.names[line] = true
			namesData.nameStems[nameStem(line)] = true
		}
		for _, line := range readDict("dict/surnames.txt") {
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
	for _, e := range []string{"ыми", "ими", "ого", "ому", "ами", "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е"} {
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
	"банк": true, "москва": true, "россия": true, "российская": true, "федерация": true,
	"область": true, "город": true, "улица": true, "дом": true, "клиент": true, "паспорт": true,
	"отделение": true, "офис": true, "договор": true, "счёт": true, "карта": true, "номер": true,
	"январь": true, "января": true, "февраль": true, "февраля": true, "март": true, "марта": true,
	"апрель": true, "апреля": true, "май": true, "мая": true, "июнь": true, "июня": true,
	"июль": true, "июля": true, "август": true, "августа": true, "сентябрь": true, "сентября": true,
	"октябрь": true, "октября": true, "ноябрь": true, "ноября": true, "декабрь": true, "декабря": true,
	"понедельник": true, "вторник": true, "среда": true, "четверг": true, "пятница": true,
	"суббота": true, "воскресенье": true,
}

var nameContext = []string{
	"клиент", "заявитель", "гражданин", "гражданка", "держатель", "владелец",
	"фио", "имя", "зовут", "меня зовут", "сотрудник", "менеджер",
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
	toks := tokenize(text)
	nt := make([]nameToken, len(toks))
	for i, t := range toks {
		nt[i].token = t
		nt[i].lower = strings.ToLower(t.text)
		nt[i].isName, nt[i].isSurname, nt[i].isSurnameGuess, nt[i].isPatr, nt[i].isInitial =
			d.classify(nt[i].lower)
	}

	var cands []int
	for i := range nt {
		t := &nt[i]
		if t.isName || t.isSurname || t.isSurnameGuess || t.isPatr || t.isInitial {
			cands = append(cands, i)
		}
	}

	covered := make([]bool, len(nt))
	var spans []pii.Span
	i := 0
	for i < len(cands) {
		ci := cands[i]
		if covered[ci] {
			i++
			continue
		}
		if i+2 < len(cands) && onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) &&
			onlyWhitespace(text, nt[cands[i+1]].end, nt[cands[i+2]].start) {
			seq := []nameToken{nt[cands[i]], nt[cands[i+1]], nt[cands[i+2]]}
			if ok, conf := d.validSeq(seq, text); ok {
				spans = append(spans, pii.Span{Start: seq[0].start, End: seq[2].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf})
				covered[cands[i]] = true
				covered[cands[i+1]] = true
				covered[cands[i+2]] = true
				i += 3
				continue
			}
		}
		if i+1 < len(cands) && onlyWhitespace(text, nt[cands[i]].end, nt[cands[i+1]].start) {
			seq := []nameToken{nt[cands[i]], nt[cands[i+1]]}
			if ok, conf := d.validSeq(seq, text); ok {
				spans = append(spans, pii.Span{Start: seq[0].start, End: seq[1].end, Category: pii.CatFullName, Detector: d.Name(), Confidence: conf})
				covered[cands[i]] = true
				covered[cands[i+1]] = true
				i += 2
				continue
			}
		}
		t := nt[cands[i]]
		if t.isName && hasLeftContext(text, t.start, nameContext, 30) {
			spans = append(spans, pii.Span{Start: t.start, End: t.end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.8})
			covered[cands[i]] = true
			i++
			continue
		}
		i++
	}
	return spans
}

func (d *namesDetector) classify(lower string) (isName, isSurname, isSurnameGuess, isPatr, isInitial bool) {
	if stopWords[lower] {
		return
	}
	isName = d.isNameToken(lower)
	isSurname, isSurnameGuess = d.isSurnameToken(lower)
	isPatr = isPatronymic(lower)
	isInitial = isInitialToken(lower)
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
	for _, e := range []string{"ыми", "ими", "ого", "ому", "ами", "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е", "ов", "ев", "ин", "ын"} {
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
	for _, suf := range []string{"ский", "цкий", "ская", "цкая", "енко", "ук", "юк", "ян", "дзе", "швили", "ых", "их", "ова", "ева", "ёва", "ина", "ына"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	for _, e := range []string{"ыми", "ими", "ого", "ому", "ами", "ах", "ым", "им", "ой", "ом", "ем", "а", "у", "ы", "е"} {
		if strings.HasSuffix(lower, e) {
			base := lower[:len(lower)-len(e)]
			for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын", "ский", "цкий", "ская", "цкая"} {
				if strings.HasSuffix(base, suf) {
					return true
				}
			}
		}
	}
	return false
}

func isPatronymic(lower string) bool {
	if hasPatSuffix(lower) {
		return true
	}
	for _, e := range []string{"а", "у", "ем", "е", "ой", "ы"} {
		if strings.HasSuffix(lower, e) {
			if hasPatSuffix(lower[:len(lower)-len(e)]) {
				return true
			}
		}
	}
	return false
}

func hasPatSuffix(s string) bool {
	for _, suf := range []string{"ович", "евич", "ич", "овна", "евна", "ична", "инична"} {
		if strings.HasSuffix(s, suf) {
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

func (d *namesDetector) validSeq(seq []nameToken, text string) (bool, float64) {
	if d.isFamous(seq) {
		return false, 0
	}
	n := len(seq)
	if n == 3 {
		if (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isName && seq[2].isPatr {
			if d.hasDictOrPatr(seq) {
				return true, 0.95
			}
		}
		if seq[0].isName && seq[1].isPatr && (seq[2].isSurname || seq[2].isSurnameGuess) {
			if d.hasDictOrPatr(seq) {
				return true, 0.95
			}
		}
		if (seq[0].isSurname || seq[0].isSurnameGuess) && seq[1].isInitial && seq[2].isInitial {
			if d.hasDictOrPatr(seq) {
				return true, 0.95
			}
		}
		if seq[0].isInitial && seq[1].isInitial && (seq[2].isSurname || seq[2].isSurnameGuess) {
			if d.hasDictOrPatr(seq) {
				return true, 0.95
			}
		}
		return false, 0
	}
	if n == 2 {
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
			if d.hasDictOrPatr(seq) && hasLeftContext(text, seq[0].start, nameContext, 30) {
				return true, 0.85
			}
		}
		return false, 0
	}
	return false, 0
}

func (d *namesDetector) hasDictOrPatr(seq []nameToken) bool {
	for _, t := range seq {
		if t.isName || t.isSurname || t.isPatr {
			return true
		}
	}
	return false
}

func (d *namesDetector) isFamous(seq []nameToken) bool {
	var stems []string
	for _, t := range seq {
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
// runes before pos.
func hasLeftContext(text string, pos int, keywords []string, window int) bool {
	prefix := text[:pos]
	r := []rune(prefix)
	if len(r) > window {
		prefix = string(r[len(r)-window:])
	}
	lower := strings.ToLower(prefix)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// hasRightContext reports whether any keyword appears within the first window
// runes after pos.
func hasRightContext(text string, pos int, keywords []string, window int) bool {
	suffix := text[pos:]
	r := []rune(suffix)
	if len(r) > window {
		suffix = string(r[:window])
	}
	lower := strings.ToLower(suffix)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
