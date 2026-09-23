package mask

// serviceWords are abbreviations and function words kept intact by the full
// and partial (words mode) strategies so the structure of an address or
// issuing authority stays readable. Keys are lowercase. Only prepositions and
// place/document abbreviations are service words; the words that name an
// issuing authority itself (e.g. "уфмс", "мвд", "россии") are part of the value
// and must be masked.
var serviceWords = map[string]bool{
	"ул": true, "улица": true, "д": true, "дом": true, "кв": true,
	"г": true, "гор": true, "город": true, "обл": true, "область": true,
	"корп": true, "стр": true, "пр-т": true, "пер": true, "пл": true,
	"наб": true, "ш": true, "р-н": true, "район": true, "край": true,
	"серия": true, "номер": true, "№": true, "года": true, "год": true,
	"г.р.": true,
}
