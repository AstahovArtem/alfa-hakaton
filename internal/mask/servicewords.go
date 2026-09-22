package mask

// serviceWordRF is the "рф" (Russian Federation) abbreviation.
const serviceWordRF = "рф"

// serviceWords are abbreviations and function words kept intact by the full
// and partial (words mode) strategies so the structure of an address or
// issuing authority stays readable. Keys are lowercase.
var serviceWords = map[string]bool{
	"ул": true, "улица": true, "д": true, "дом": true, "кв": true,
	"г": true, "гор": true, "город": true, "обл": true, "область": true,
	"корп": true, "стр": true, "пр-т": true, "пер": true, "пл": true,
	"наб": true, "ш": true, "р-н": true, "район": true, "край": true,
	"респ": true, "республика": true, "россии": true, serviceWordRF: true,
	"овд": true, "уфмс": true, "мвд": true, "гу": true, "тп": true,
	"отделом": true, "отделением": true, "управлением": true,
	"серия": true, "номер": true, "№": true, "года": true, "год": true,
	"г.р.": true,
}
