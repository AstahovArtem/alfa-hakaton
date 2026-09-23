package pii

// Category identifies a type of personal data.
type Category string

const (
	CatFullName        Category = "full_name"
	CatBirthDate       Category = "birth_date"
	CatBirthPlace      Category = "birth_place"
	CatPassport        Category = "passport" // серия и номер паспорта РФ
	CatCitizenship     Category = "citizenship"
	CatPassportIssuer  Category = "passport_issuer" // орган, выдавший паспорт
	CatDivisionCode    Category = "division_code"   // код подразделения
	CatPassportDate    Category = "passport_date"   // дата выдачи
	CatDriverLicense   Category = "driver_license"
	CatAddress         Category = "address"
	CatEmail           Category = "email"
	CatPhone           Category = "phone"
	CatINN             Category = "inn"
	CatCardNumber      Category = "card_number"
	CatCVV             Category = "cvv"
	CatPIN             Category = "pin"
	CatCardHolder      Category = "card_holder"
	CatSNILS           Category = "snils"            // доп. документ
	CatForeignPassport Category = "foreign_passport" // загранпаспорт, доп. документ
	CatIDDocument      Category = "id_document"      // военный билет, ВНЖ, свидетельство о рождении, удостоверение военнослужащего, паспорт моряка
	CatDate            Category = "date"             // дата без контекста; уточняется до birth_date/passport_date
)

// Span is a detected PII fragment. Positions are byte offsets into the original UTF-8 text.
type Span struct {
	Start, End int
	Category   Category
	Detector   string  // detector name
	Confidence float64 // 0..1
}

// Text is the input to a detector. Raw is the original UTF-8 text; Lower is
// strings.ToLower(Raw) computed once per pipeline run. When len(Lower) !=
// len(Raw) (rare characters such as "İ" change byte length when lowercased),
// Lower must not be used for byte positions; detectors fall back to the Raw
// path in that case.
type Text struct {
	Raw   string
	Lower string
}

// LowerOK reports whether Lower has the same byte length as Raw, so byte
// offsets into Raw are valid into Lower.
func (t Text) LowerOK() bool {
	return len(t.Lower) == len(t.Raw)
}

// Result of running the pipeline.
type Result struct {
	Spans []Span // sorted by Start, non-overlapping after resolve
}

// Counts returns the number of spans per category.
func (r Result) Counts() map[Category]int {
	counts := make(map[Category]int)
	for _, s := range r.Spans {
		counts[s.Category]++
	}
	return counts
}
