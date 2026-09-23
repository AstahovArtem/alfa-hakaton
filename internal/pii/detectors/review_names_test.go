package detectors

import (
	"testing"

	"pdn-shield/internal/pii"
)

// Regressions from the production PII-leak review for person names (full_name
// and card_holder). Every case runs through the default pipeline, the same way
// a request reaches /process, not just the names detector in isolation.

// B6a: a client/role marker on either side of a famous person's name, within
// the same sentence, must disable the famous-person suppression, because the
// name is then the client's own (or another real person's, e.g. a
// guarantor's), not a historical reference.
func TestReviewFamousNameWithRoleMarker(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"dashRight", "Лев Толстой — мой поручитель"},
		{"bareRight", "Лев Толстой мой поручитель по кредиту"},
		{"left", "поручитель — Лев Толстой"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if !hasCategory(t, res, pii.CatFullName) {
				t.Errorf("famous name with a role marker should be PII: %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

// B6a traps: a famous person's name must stay unmasked when there is no
// client/role marker nearby, even next to other words that could look like
// context (a profession, a literary reference, a monument).
func TestReviewFamousNameTrapsStayUnmasked(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"fullNameWithProfession", "Поэт Александр Сергеевич Пушкин родился в Москве"},
		{"novelGenitive", "роман Льва Толстого «Война и мир»"},
		{"monumentDative", "памятник Пушкину"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if hasCategory(t, res, pii.CatFullName) {
				t.Errorf("famous name without a role marker should stay unmasked: %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

// B6b: a first name + patronymic without a surname is always a person and
// must be masked; the famous-person exception only ever applies when the
// surname is present too (see TestReviewFamousSurnamePrecedesPatr below).
func TestReviewBarePatronymicIsMasked(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"actionVerbRight", "Александр Сергеевич позвонил вчера"},
		{"famousPairEndOfPhrase", "Фёдора Михайловича"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if !hasCategory(t, res, pii.CatFullName) {
				t.Errorf("bare name+patronymic should be PII: %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

// The famous-person exception still applies to a name+patronymic pair when
// the surname sits directly in front of it, since the full name is then
// actually present in the text (just not merged into one span by the
// surname+name+patronymic matcher, e.g. a genitive declension).
func TestReviewFamousSurnamePrecedesPatr(t *testing.T) {
	res := runPipeline(t, "Гагарина Юрия Алексеевича")
	if hasCategory(t, res, pii.CatFullName) {
		t.Errorf("famous full name (surname before name+patronymic) should stay unmasked: got %+v", res.Spans)
	}
}

// B9: a lowercase Latin name after an explicit name label must be detected,
// in both English and Russian labels; unlabeled lowercase Latin words must
// never become a name (false-positive guard).
func TestReviewLowercaseLatinNameAfterLabel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"nameColonLower", "name: tigran avakyan", "tigran avakyan"},
		{"fioColonLower", "ФИО: tigran avakyan", "tigran avakyan"},
		{"nameColonMixedCase", "Name: Tigran Avakyan", "Tigran Avakyan"},
		{"clientColonLower", "client: ivan petrov", "ivan petrov"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
		})
	}
}

func TestReviewLowercaseLatinNameNoLabelNegative(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plainEnglishSentence", "hello, my order has not arrived yet"},
		{"labelFarAway", "Клиент: здравствуйте, у меня вопрос про account and payment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runPipeline(t, c.in)
			if hasCategory(t, res, pii.CatFullName) {
				t.Errorf("unlabeled lowercase Latin words should not be a name: %q, got %+v", c.in, res.Spans)
			}
		})
	}
}

// B16: a 2-4 word Latin cardholder name after a holder label must be covered
// in full, including a 4-word name (e.g. a middle name and a surname).
func TestReviewCardholderFourWordName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cardholderLabel", "cardholder JOHN RONALD REUEL TOLKIEN", "JOHN RONALD REUEL TOLKIEN"},
		{"derzhatelKartyLabel", "держатель карты JOHN RONALD REUEL TOLKIEN", "JOHN RONALD REUEL TOLKIEN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatCardHolder, c.in, c.want)
		})
	}
}

// Forms that must keep working: lowercase Russian full names after a label,
// hyphenated surnames, and an uppercase Cyrillic client signature.
func TestReviewExistingFormsStillWork(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lowercaseRussianAfterLabel", "фио: ахметзянова зульфия ильгизовна", "ахметзянова зульфия ильгизовна"},
		{"hyphenatedSurname", "Салтыков-Щедрин Михаил", "Салтыков-Щедрин Михаил"},
		{"uppercaseClientFIO", "КЛИЕНТ ИВАНОВ ИВАН ИВАНОВИЧ", "ИВАНОВ ИВАН ИВАНОВИЧ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertSpanValue(t, runPipeline(t, c.in), pii.CatFullName, c.in, c.want)
		})
	}
}
