// Command gen generates a blind accuracy dataset: Russian phrases with PII
// values that the detectors have not been tuned on. The output is JSONL in the
// same format as internal/pii/testdata/dataset.jsonl.
//
// Usage:
//
//	go run ./internal/pii/testdata/gen -n 2000 -seed 42 -out internal/pii/testdata/blind.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// record is one line of the output JSONL.
type record struct {
	ID    string `json:"id"`
	Text  string `json:"text"`
	Spans []span `json:"spans"`
}

// span is an expected PII fragment with byte offsets.
type span struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Value    string `json:"value,omitempty"`
	Category string `json:"category"`
}

// gen holds the RNG and loaded dictionaries.
type gen struct {
	rng      *rand.Rand
	names    []string
	surnames []string
	cities   []string
	famous   [][]string
	streets  []string
}

func main() {
	n := flag.Int("n", 2000, "number of records")
	seed := flag.Int64("seed", 42, "random seed")
	out := flag.String("out", "internal/pii/testdata/blind.jsonl", "output path")
	flag.Parse()

	g := newGen(*seed)
	records := g.generate(*n)

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", *out, err)
		os.Exit(1)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			os.Exit(1)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d records to %s\n", len(records), *out)
}

// newGen loads the dictionaries and builds a generator.
func newGen(seed int64) *gen {
	g := &gen{
		rng:      rand.New(rand.NewSource(seed)),
		names:    readLines(filepath.Join("internal", "pii", "detectors", "dict", "first_names.txt")),
		surnames: readLines(filepath.Join("internal", "pii", "detectors", "dict", "surnames.txt")),
		cities:   readLines(filepath.Join("internal", "pii", "detectors", "dict", "cities.txt")),
		streets: []string{
			"Ленина", "Пушкина", "Советская", "Красная", "Малышева", "Кирова",
			"Гагарина", "Мира", "Победы", "Ленинградская", "Тверская", "Октябрьская",
			"Садовая", "Молодёжная", "Центральная", "Школьная", "Лесная", "Парковая",
			"Заречная", "Набережная", "Комсомольская", "Первомайская", "Юбилейная",
		},
	}
	for _, line := range readLines(filepath.Join("internal", "pii", "detectors", "dict", "famous.txt")) {
		g.famous = append(g.famous, strings.Fields(line))
	}
	return g
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
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

// generate produces n records, 80% positive and 20% negative.
func (g *gen) generate(n int) []record {
	records := make([]record, 0, n)
	for i := 0; i < n; i++ {
		if g.rng.Float64() < 0.2 {
			records = append(records, g.negativeRecord(i))
		} else {
			records = append(records, g.positiveRecord(i))
		}
	}
	return records
}

var placeholderRe = regexp.MustCompile(`\{([a-z_]+)\}`)

// fill replaces placeholders in tmpl with values and returns the text plus the
// byte-offset spans of each value.
func fill(tmpl string, vals map[string]string) (string, []span) {
	var b strings.Builder
	var spans []span
	pos := 0
	for _, m := range placeholderRe.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(tmpl[pos:m[0]])
		name := tmpl[m[2]:m[3]]
		val := vals[name]
		spStart := b.Len()
		b.WriteString(val)
		spans = append(spans, span{Start: spStart, End: b.Len(), Category: categoryFor(name)})
		pos = m[1]
	}
	b.WriteString(tmpl[pos:])
	return b.String(), spans
}

// categoryFor maps a placeholder name to its PII category.
func categoryFor(name string) string {
	switch name {
	case "full_name":
		return "full_name"
	case "phone":
		return "phone"
	case "passport":
		return "passport"
	case "birth_date":
		return "birth_date"
	case "address":
		return "address"
	case "card":
		return "card_number"
	case "cvv":
		return "cvv"
	case "email":
		return "email"
	case "inn":
		return "inn"
	case "snils":
		return "snils"
	case "issuer":
		return "passport_issuer"
	case "division":
		return "division_code"
	case "birth_place":
		return "birth_place"
	case "citizenship":
		return "citizenship"
	case "driver_license":
		return "driver_license"
	case "foreign_passport":
		return "foreign_passport"
	case "card_holder":
		return "card_holder"
	default:
		return ""
	}
}

// positiveRecord builds one record with PII from a random template.
func (g *gen) positiveRecord(i int) record {
	tmpl := g.positiveTemplates()[g.rng.Intn(len(g.positiveTemplates()))]
	vals := g.valuesFor(tmpl)
	text, spans := fill(tmpl, vals)
	return record{ID: fmt.Sprintf("blind-%05d", i), Text: text, Spans: spans}
}

// negativeRecord builds one record with no PII (a trap).
func (g *gen) negativeRecord(i int) record {
	tmpl := g.negativeTemplates()[g.rng.Intn(len(g.negativeTemplates()))]
	text, _ := fill(tmpl, nil)
	return record{ID: fmt.Sprintf("blind-neg-%05d", i), Text: text, Spans: nil}
}

// valuesFor generates a value for every placeholder used in tmpl.
func (g *gen) valuesFor(tmpl string) map[string]string {
	vals := make(map[string]string)
	for _, m := range placeholderRe.FindAllStringSubmatch(tmpl, -1) {
		name := m[1]
		if _, ok := vals[name]; ok {
			continue
		}
		vals[name] = g.value(name)
	}
	return vals
}

// value generates a value for a placeholder name.
func (g *gen) value(name string) string {
	switch name {
	case "full_name":
		return g.fullName()
	case "full_name_gen":
		return g.fullNameGenitive()
	case "phone":
		return g.phone()
	case "passport":
		return g.passport()
	case "birth_date":
		return g.birthDate()
	case "address":
		return g.address()
	case "card":
		return g.card()
	case "cvv":
		return g.cvv()
	case "email":
		return g.email()
	case "inn":
		return g.inn()
	case "snils":
		return g.snils()
	case "issuer":
		return g.issuer()
	case "division":
		return g.division()
	case "birth_place":
		return g.birthPlace()
	case "citizenship":
		return g.citizenship()
	case "driver_license":
		return g.driverLicense()
	case "foreign_passport":
		return g.foreignPassport()
	case "card_holder":
		return g.cardHolder()
	default:
		return ""
	}
}

// fullName returns a nominative full name.
func (g *gen) fullName() string {
	return synthFullName(g.rng, g.names, g.surnames)
}

// fullNameGenitive returns a genitive full name for "заявление от".
func (g *gen) fullNameGenitive() string {
	return synthFullNameGenitive(g.rng, g.names, g.surnames)
}

// phone returns a phone in a random format.
func (g *gen) phone() string {
	d := synthPhoneDigits(g.rng)
	// d is 11 digits starting with 7. Groups: area (3), mid (3), tail (2), tail (2).
	area, mid, t1, t2 := d[1:4], d[4:7], d[7:9], d[9:11]
	formats := []string{
		"+7 (%s) %s-%s-%s",
		"8%s%s%s",
		"8 %s %s %s %s",
		"+7-%s-%s-%s-%s",
		"8(%s)%s-%s-%s",
		"7 %s %s %s %s",
	}
	f := formats[g.rng.Intn(len(formats))]
	switch f {
	case "+7 (%s) %s-%s-%s":
		return fmt.Sprintf(f, area, mid, t1, t2)
	case "8%s%s%s":
		return "8" + area + mid + t1 + t2
	case "8 %s %s %s %s":
		return fmt.Sprintf("8 %s %s %s %s", area, mid, t1, t2)
	case "+7-%s-%s-%s-%s":
		return fmt.Sprintf("+7-%s-%s-%s-%s", area, mid, t1, t2)
	case "8(%s)%s-%s-%s":
		return fmt.Sprintf("8(%s)%s-%s-%s", area, mid, t1, t2)
	default:
		return fmt.Sprintf("7 %s %s %s %s", area, mid, t1, t2)
	}
}

// passport returns a passport in a random format.
func (g *gen) passport() string {
	d := synthPassportDigits(g.rng)
	formats := []string{
		"%s %s",
		"%s%s",
		"%s %s %s",
		"серия %s номер %s",
	}
	f := formats[g.rng.Intn(len(formats))]
	switch f {
	case "%s %s":
		return d[0:4] + " " + d[4:10]
	case "%s%s":
		return d
	case "%s %s %s":
		return d[0:2] + " " + d[2:4] + " " + d[4:10]
	default:
		return "серия " + d[0:4] + " номер " + d[4:10]
	}
}

// birthDate returns a birth date in a random format.
func (g *gen) birthDate() string {
	formats := []string{
		"%s.%s.%s",
		"%s %s %s года",
		"%s-%s-%s",
	}
	f := formats[g.rng.Intn(len(formats))]
	day, month, year := synthDateParts(g.rng)
	switch f {
	case "%s.%s.%s":
		return fmt.Sprintf("%s.%s.%s", day, month, year)
	case "%s %s %s года":
		return fmt.Sprintf("%s %s %s года", day, monthGenitive(atoi(month)), year)
	default:
		return fmt.Sprintf("%s-%s-%s", year, month, day)
	}
}

// address returns a full address.
func (g *gen) address() string {
	city := g.city()
	street := g.streets[g.rng.Intn(len(g.streets))]
	house := 1 + g.rng.Intn(200)
	apt := 1 + g.rng.Intn(200)
	formats := []string{
		"г. %s, ул. %s, д. %d, кв. %d",
		"г. %s, ул. %s, д. %d",
		"%s, %s %d",
	}
	f := formats[g.rng.Intn(len(formats))]
	switch f {
	case "г. %s, ул. %s, д. %d, кв. %d":
		return fmt.Sprintf(f, city, street, house, apt)
	case "г. %s, ул. %s, д. %d":
		return fmt.Sprintf(f, city, street, house)
	default:
		return fmt.Sprintf("%s, %s %d", cityPrepositional(city), street, house)
	}
}

// birthPlace returns a place of birth.
func (g *gen) birthPlace() string {
	city := g.city()
	formats := []string{
		"г. %s",
		"%s",
		"города %s",
	}
	f := formats[g.rng.Intn(len(formats))]
	switch f {
	case "г. %s":
		return "г. " + city
	case "города %s":
		return "города " + cityGenitive(city)
	default:
		return cityPrepositional(city)
	}
}

// card returns a card number in a random format.
func (g *gen) card() string {
	d := synthCardDigits(g.rng)
	formats := []string{
		"%s %s %s %s",
		"%s",
		"%s-%s-%s-%s",
	}
	f := formats[g.rng.Intn(len(formats))]
	switch f {
	case "%s %s %s %s":
		return fmt.Sprintf("%s %s %s %s", d[0:4], d[4:8], d[8:12], d[12:16])
	case "%s":
		return d
	default:
		return fmt.Sprintf("%s-%s-%s-%s", d[0:4], d[4:8], d[8:12], d[12:16])
	}
}

// cvv returns a 3-digit CVV.
func (g *gen) cvv() string {
	return fmt.Sprintf("%03d", g.rng.Intn(1000))
}

// email returns an email address.
func (g *gen) email() string {
	domains := []string{"mail.ru", "yandex.ru", "gmail.com", "example.com", "bank.ru"}
	user := translit(g.surnames[g.rng.Intn(len(g.surnames))])
	return user + "@" + domains[g.rng.Intn(len(domains))]
}

// inn returns a 12-digit INN.
func (g *gen) inn() string {
	return synthINNDigits(g.rng)
}

// snils returns a SNILS in a random format.
func (g *gen) snils() string {
	d := synthSNILSDigits(g.rng)
	if g.rng.Intn(2) == 0 {
		return fmt.Sprintf("%s-%s-%s %s", d[0:3], d[3:6], d[6:9], d[9:11])
	}
	return d
}

// issuer returns a passport issuer.
func (g *gen) issuer() string {
	city := g.city()
	orgs := []string{
		"ОУФМС России по г. %s",
		"ГУ МВД России по г. %s",
		"УФМС России по г. %s",
		"ОМВД России по району Хамовники",
		"ОВД района Хамовники",
	}
	o := orgs[g.rng.Intn(len(orgs))]
	if strings.Contains(o, "%s") {
		return fmt.Sprintf(o, city)
	}
	return o
}

// division returns a division code.
func (g *gen) division() string {
	return fmt.Sprintf("%03d-%03d", g.rng.Intn(1000), g.rng.Intn(1000))
}

// citizenship returns a citizenship.
func (g *gen) citizenship() string {
	opts := []string{"РФ", "Российская Федерация", "России", "Республики Казахстан", "Беларуси"}
	return opts[g.rng.Intn(len(opts))]
}

// driverLicense returns a driver license in a random format.
func (g *gen) driverLicense() string {
	region := 1 + g.rng.Intn(90)
	if g.rng.Intn(2) == 0 {
		return fmt.Sprintf("%02d %02d %06d", region, 1+g.rng.Intn(90), g.rng.Intn(1000000))
	}
	return fmt.Sprintf("%02dАА %06d", region, g.rng.Intn(1000000))
}

// foreignPassport returns a foreign passport number.
func (g *gen) foreignPassport() string {
	return fmt.Sprintf("%02d %07d", 1+g.rng.Intn(90), g.rng.Intn(10000000))
}

// cardHolder returns a Latin card holder name.
func (g *gen) cardHolder() string {
	first := g.names[g.rng.Intn(len(g.names))]
	surname := g.surnames[g.rng.Intn(len(g.surnames))]
	return strings.ToUpper(translit(first) + " " + translit(surname))
}

// city returns a random city in the nominative case.
func (g *gen) city() string {
	return g.cities[g.rng.Intn(len(g.cities))]
}

// positiveTemplates returns the pool of positive phrase templates.
func (g *gen) positiveTemplates() []string {
	return []string{
		// Анкета
		"ФИО: {full_name}, дата рождения {birth_date}, место рождения: {birth_place}",
		"Анкета: {full_name}, паспорт {passport}, выдан {issuer}, код подразделения {division}",
		"Заявитель: {full_name}, гражданство {citizenship}, адрес регистрации: {address}",
		"Клиент {full_name}, телефон {phone}, email {email}",
		"Паспортные данные: {full_name}, серия и номер {passport}, дата рождения {birth_date}",
		"Регистрация: {full_name}, дата рождения {birth_date}, адрес {address}, тел. {phone}",
		"Личные данные: {full_name}, ИНН {inn}, СНИЛС {snils}",
		"Анкета клиента: {full_name}, дата рождения {birth_date}, место рождения: {birth_place}, гражданство {citizenship}",
		"Данные заявителя: {full_name}, паспорт {passport}, выдан {issuer}, код подразделения {division}",
		"Заполните анкету: ФИО {full_name}, дата рождения {birth_date}, адрес {address}",
		// Переписка с поддержкой
		"Здравствуйте, меня зовут {full_name}, мой номер {phone}, помогите с заказом",
		"Подскажите, я {full_name}, мой email {email}, не могу войти в приложение",
		"Добрый день, я {full_name}, паспорт {passport}, хочу восстановить доступ",
		"Уважаемая поддержка, я {full_name}, мой телефон {phone}, проблема с картой {card}",
		"Здравствуйте, я {full_name}, дата рождения {birth_date}, подтвердите личность",
		"Помогите, пожалуйста, я {full_name}, мой ИНН {inn}",
		"Добрый день, я {full_name}, СНИЛС {snils}, не могу получить выплату",
		"Здравствуйте, я {full_name}, адрес {address}, жду доставку",
		"Я {full_name}, мой номер {phone}, карта {card}, CVV {cvv}",
		"Поддержка, я {full_name}, email {email}, телефон {phone}",
		// Заявление
		"Заявление от {full_name_gen}, паспорт {passport}, выдан {issuer}",
		"Прошу выдать справку, {full_name}, дата рождения {birth_date}",
		"Заявление: {full_name}, адрес {address}, телефон {phone}",
		"Прошу пересчитать, {full_name}, ИНН {inn}, СНИЛС {snils}",
		"Заявление о выдаче: {full_name}, паспорт {passport}, код подразделения {division}",
		"От {full_name_gen}: прошу изменить адрес на {address}",
		"Заявление от {full_name_gen}, дата рождения {birth_date}, место рождения: {birth_place}",
		"Прошу оформить, {full_name}, гражданство {citizenship}",
		"Заявление: {full_name}, водительское удостоверение {driver_license}",
		"От {full_name_gen}, паспорт {passport}, телефон {phone}",
		// Чат с ботом
		"Меня зовут {full_name}, мой номер {phone}",
		"Я {full_name}, хочу узнать баланс карты {card}",
		"Мой email {email}, имя {full_name}",
		"Подтвердите, что вы {full_name}, дата рождения {birth_date}",
		"Мой паспорт {passport}, я {full_name}",
		"Я {full_name}, адрес {address}",
		"Мой ИНН {inn}, ФИО {full_name}",
		"Я {full_name}, СНИЛС {snils}",
		"Мой телефон {phone}, я {full_name}",
		"Я {full_name}, карта {card}, CVV {cvv}",
		// Внутренняя заметка менеджера
		"Клиент {full_name}, телефон {phone}, обратился по вопросу кредита",
		"Заметка: {full_name}, паспорт {passport}, выдан {issuer}",
		"Клиент {full_name}, адрес {address}, нужна проверка",
		"Менеджер: {full_name}, email {email}, карта {card}",
		"Клиент {full_name}, дата рождения {birth_date}, место рождения: {birth_place}",
		"Заметка: {full_name}, ИНН {inn}, СНИЛС {snils}",
		"Клиент {full_name}, водительское {driver_license}",
		"Менеджер: {full_name}, загранпаспорт {foreign_passport}",
		"Клиент {full_name}, телефон {phone}, адрес {address}",
		"Заметка: {full_name}, паспорт {passport}, код подразделения {division}",
		// SMS
		"Ваш код безопасности для {full_name}: {cvv}",
		"Уважаемый {full_name}, ваш заказ готов, телефон {phone}",
		"Здравствуйте, {full_name}, ваша карта {card} заблокирована",
		"Уважаемый {full_name}, подтвердите операцию по карте {card}",
		"Ваш номер {phone} подтверждён, {full_name}",
		"Уважаемый {full_name}, ваш email {email} изменён",
		"Здравствуйте, {full_name}, ваш паспорт {passport} на проверке",
		"Уважаемый {full_name}, ваша заявка принята, дата рождения {birth_date}",
		"Ваш код безопасности: {cvv}, {full_name}",
		"Уважаемый {full_name}, ваш адрес {address} подтверждён",
		// Письмо
		"Уважаемый {full_name}, ваш договор готов, телефон {phone}",
		"Здравствуйте, {full_name}, подтвердите адрес {address}",
		"Уважаемый {full_name}, ваша карта {card} готова к выдаче",
		"Здравствуйте, {full_name}, ваш ИНН {inn} подтверждён",
		"Уважаемый {full_name}, ваш СНИЛС {snils} на проверке",
		"Здравствуйте, {full_name}, ваш паспорт {passport} готов",
		"Уважаемый {full_name}, ваша дата рождения {birth_date} уточнена",
		"Здравствуйте, {full_name}, ваш email {email} подтверждён",
		"Уважаемый {full_name}, ваше водительское {driver_license} готово",
		"Здравствуйте, {full_name}, ваш загранпаспорт {foreign_passport} готов",
		// Держатель карты
		"Держатель карты {card_holder}, карта {card}, CVV {cvv}",
		"{card_holder} {card}",
		"Имя на карте {card_holder}, номер {card}",
		"Cardholder {card_holder}, card {card}",
		"Держатель {card_holder}, карта {card}",
	}
}

// negativeTemplates returns the pool of negative (trap) templates.
func (g *gen) negativeTemplates() []string {
	famous := g.famous[g.rng.Intn(len(g.famous))]
	famousName := strings.Join(famous, " ")
	return []string{
		"поэт " + famousName + " родился в 1799 году",
		"стихи " + famousName + " изучают в школе",
		"отделение банка по адресу ул. Ленина, 1",
		"филиал банка: г. Москва, ул. Тверская, д. 10",
		"банкомат по адресу: г. Москва, ул. Ленина, д. 5",
		"доп. офис: г. Москва, ул. Ленина, д. 5",
		"головной офис: г. Москва, ул. Ленина, д. 5",
		"Номер заказа 1234567890",
		"сумма 15000 рублей",
		"версия 1.2.3",
		"в 14:30",
		"в 1990 году",
		"код 1234",
		"число 1234567890",
		"счёт 40817810099910004312",
		"номер 1234567890",
		"телефон 1234567890",
		"дата 31.02.2020",
		"ИНН 500100732258",
		"карта 4111 1111 1111 1112",
		"паспорт 0000 123456",
		"снилс 112-233-445 96",
		"загранпаспорт 71 123456",
		"код 1234",
		"дата 32.01.2020",
		"ИНН 3664069398",
		"улица Иванова",
		"Москва — столица",
		"IVAN IVANOV",
		"держатель карты VISA MASTERCARD",
	}
}

// synthFullName builds a nominative full name.
func synthFullName(rng *rand.Rand, names, surnames []string) string {
	first := names[rng.Intn(len(names))]
	surname := surnames[rng.Intn(len(surnames))]
	patr := patrM[rng.Intn(len(patrM))]
	if isFemaleName(first) {
		surname = feminize(surname)
		patr = patrF[rng.Intn(len(patrF))]
	}
	return capitalize(surname) + " " + capitalize(first) + " " + patr
}

// synthFullNameGenitive builds a genitive full name.
func synthFullNameGenitive(rng *rand.Rand, names, surnames []string) string {
	first := names[rng.Intn(len(names))]
	surname := surnames[rng.Intn(len(surnames))]
	patr := patrM[rng.Intn(len(patrM))]
	female := isFemaleName(first)
	if female {
		surname = feminize(surname)
		patr = patrF[rng.Intn(len(patrF))]
	}
	return genitiveSurname(capitalize(surname), female) + " " + genitiveName(capitalize(first), female) + " " + genitivePatr(patr)
}

var patrM = []string{"Александрович", "Андреевич", "Борисович", "Васильевич", "Викторович",
	"Владимирович", "Дмитриевич", "Евгеньевич", "Иванович", "Игоревич", "Константинович",
	"Михайлович", "Николаевич", "Олегович", "Павлович", "Петрович", "Сергеевич", "Фёдорович", "Юрьевич"}

var patrF = []string{"Александровна", "Андреевна", "Борисовна", "Васильевна", "Викторовна",
	"Владимировна", "Дмитриевна", "Евгеньевна", "Ивановна", "Игоревна", "Константиновна",
	"Михайловна", "Николаевна", "Олеговна", "Павловна", "Петровна", "Сергеевна", "Фёдоровна", "Юрьевна"}

// maleNamesEndingInVowel are male first names that end in -а or -я and would
// otherwise be mistaken for female names.
var maleNamesEndingInVowel = map[string]bool{
	"никита": true, "аникита": true, "илья": true, "фома": true, "кузьма": true,
	"савва": true, "данила": true, "лука": true, "зосима": true, "вавила": true,
	"добрыня": true, "сила": true,
}

func isFemaleName(name string) bool {
	lower := strings.ToLower(name)
	if maleNamesEndingInVowel[lower] {
		return false
	}
	for _, suf := range []string{"а", "я", "ия", "ья"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func feminize(s string) string {
	lower := strings.ToLower(s)
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(lower, suf) {
			return s[:len(s)-len(suf)] + suf + "а"
		}
	}
	return s
}

func genitiveSurname(s string, female bool) string {
	lower := strings.ToLower(s)
	if female {
		for _, suf := range []string{"ова", "ева", "ёва", "ина", "ына"} {
			if strings.HasSuffix(lower, suf) {
				return dropLastRune(s) + "ой"
			}
		}
		return s
	}
	for _, suf := range []string{"ов", "ев", "ёв", "ин", "ын"} {
		if strings.HasSuffix(lower, suf) {
			return s + "а"
		}
	}
	return s
}

func genitiveName(s string, female bool) string {
	lower := strings.ToLower(s)
	if female {
		for _, suf := range []string{"ия", "ья"} {
			if strings.HasSuffix(lower, suf) {
				return dropLastRune(s) + "и"
			}
		}
		for _, suf := range []string{"а", "я"} {
			if strings.HasSuffix(lower, suf) {
				return dropLastRune(s) + "ы"
			}
		}
		return s
	}
	for _, suf := range []string{"ий", "ей"} {
		if strings.HasSuffix(lower, suf) {
			return dropLastRunes(s, 2) + "я"
		}
	}
	for _, suf := range []string{"й"} {
		if strings.HasSuffix(lower, suf) {
			return dropLastRune(s) + "я"
		}
	}
	if strings.HasSuffix(lower, "ь") {
		return dropLastRune(s) + "я"
	}
	return s + "а"
}

func genitivePatr(p string) string {
	lower := strings.ToLower(p)
	for _, suf := range []string{"овна", "евна", "ична", "инична"} {
		if strings.HasSuffix(lower, suf) {
			return p + "ы"
		}
	}
	for _, suf := range []string{"ович", "евич", "ич"} {
		if strings.HasSuffix(lower, suf) {
			return p + "а"
		}
	}
	return p
}

// dropLastRune removes the last rune of s.
func dropLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:len(r)-1])
}

// dropLastRunes removes the last n runes of s.
func dropLastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return ""
	}
	return string(r[:len(r)-n])
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

// cityPrepositional returns the prepositional case of a city ("в Москве").
func cityPrepositional(city string) string {
	lower := strings.ToLower(city)
	for _, suf := range []string{"ск", "цк", "нск", "бург", "град"} {
		if strings.HasSuffix(lower, suf) {
			return city + "е"
		}
	}
	if strings.HasSuffix(lower, "а") {
		return dropLastRune(city) + "е"
	}
	if strings.HasSuffix(lower, "ь") {
		return dropLastRune(city) + "и"
	}
	if strings.HasSuffix(lower, "й") {
		return dropLastRune(city) + "е"
	}
	return city + "е"
}

// cityGenitive returns the genitive case of a city ("города Москвы").
func cityGenitive(city string) string {
	lower := strings.ToLower(city)
	if strings.HasSuffix(lower, "а") {
		return dropLastRune(city) + "ы"
	}
	if strings.HasSuffix(lower, "я") {
		return dropLastRune(city) + "и"
	}
	if strings.HasSuffix(lower, "ь") {
		return dropLastRune(city) + "и"
	}
	return city + "а"
}

// synthPhoneDigits returns 11 phone digits starting with 7.
func synthPhoneDigits(rng *rand.Rand) string {
	return "7" + "9" + randDigits(rng, 9)
}

// synthPassportDigits returns 10 passport digits.
func synthPassportDigits(rng *rand.Rand) string {
	return "4" + randDigits(rng, 3) + randDigits(rng, 6)
}

// synthCardDigits returns 16 Luhn-valid card digits.
func synthCardDigits(rng *rand.Rand) string {
	bin := "4"
	if rng.Intn(2) == 0 {
		bin = "5"
	}
	bin += randDigits(rng, 2)
	body := bin + randDigits(rng, 12)
	return body + string(luhnCheckDigit(body))
}

// synthINNDigits returns a 12-digit INN.
func synthINNDigits(rng *rand.Rand) string {
	base := randDigits(rng, 10)
	n11 := innControl(base, []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8})
	n12 := innControl(base+string(n11), []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8})
	return base + string(n11) + string(n12)
}

// synthSNILSDigits returns an 11-digit SNILS.
func synthSNILSDigits(rng *rand.Rand) string {
	base := randDigits(rng, 9)
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(base[i]-'0') * (9 - i)
	}
	var control int
	if sum < 100 {
		control = sum
	} else if sum == 100 || sum == 101 {
		control = 0
	} else {
		control = sum % 101
		if control == 100 {
			control = 0
		}
	}
	return base + twoDigits(control)
}

// synthDateParts returns day, month, year of a valid date.
func synthDateParts(rng *rand.Rand) (string, string, string) {
	year := 1950 + rng.Intn(56)
	month := 1 + rng.Intn(12)
	day := 1 + rng.Intn(daysInMonth(year, month))
	return twoDigits(day), twoDigits(month), itoa(year)
}

func innControl(d string, weights []int) byte {
	sum := 0
	for i, w := range weights {
		sum += int(d[i]-'0') * w
	}
	return byte('0' + sum%11%10)
}

func luhnCheckDigit(d string) byte {
	sum := 0
	double := true
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
	return byte('0' + (10-sum%10)%10)
}

func daysInMonth(year, month int) int {
	dm := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if month == 2 && isLeapYear(year) {
		return 29
	}
	return dm[month-1]
}

func isLeapYear(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}

var monthGenitiveList = []string{"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря"}

func monthGenitive(m int) string {
	if m < 1 || m > 12 {
		return ""
	}
	return monthGenitiveList[m-1]
}

func randDigits(rng *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + rng.Intn(10)))
	}
	return b.String()
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// translit converts a Cyrillic name to a Latin approximation for card holders.
func translit(s string) string {
	m := map[rune]string{
		'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
		'ж': "zh", 'з': "z", 'и': "i", 'й': "i", 'к': "k", 'л': "l", 'м': "m",
		'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
		'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch",
		'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if v, ok := m[r]; ok {
			b.WriteString(v)
		}
	}
	return b.String()
}
