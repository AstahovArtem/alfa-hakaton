package detectors

import (
	"strings"
	"unicode/utf8"

	"pdn-shield/internal/pii"
)

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
		spans = append(
			spans,
			pii.Span{Start: toks[a].start, End: end, Category: pii.CatFullName, Detector: d.Name(), Confidence: 0.9},
		)
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
		j := foreignNameRunEnd(text, nt, covered, i)
		runLen := j - i + 1
		if runLen >= 2 && runLen <= 4 &&
			hasLeftContext(t, nt[i].start, foreignNameContext, 40) &&
			endsPhrase(text, nt[j].end) {
			spans = append(
				spans,
				pii.Span{
					Start:      nt[i].start,
					End:        nt[j].end,
					Category:   pii.CatFullName,
					Detector:   d.Name(),
					Confidence: 0.9,
				},
			)
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

// foreignNameRunEnd returns the index of the last token in a contiguous run of
// foreign-name candidates starting at i.
func foreignNameRunEnd(text string, nt []nameToken, covered []bool, i int) int {
	j := i
	for j+1 < len(nt) && !covered[j+1] && isForeignNameCandidate(nt[j+1]) &&
		onlyWhitespace(text, nt[j].end, nt[j+1].start) &&
		!strings.Contains(text[nt[j].end:nt[j+1].start], "\n") {
		j++
	}
	return j
}

// isForeignNameCandidate reports whether a token could be part of a foreign
// full name: capitalised, not a known Russian name/surname/patronymic, not a
// stopword.
func isForeignNameCandidate(t nameToken) bool {
	if t.isNameLike() {
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
