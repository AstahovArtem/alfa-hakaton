package mask

import (
	"hash/fnv"
)

func fnvHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

func luhnValid(s string) bool {
	d := digitsOnly(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	double := false
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
	return sum%10 == 0
}

func innValid(s string) bool {
	d := digitsOnly(s)
	if len(d) != 12 {
		return false
	}
	w1 := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	w2 := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s1, s2 := 0, 0
	for i := 0; i < 10; i++ {
		s1 += int(d[i]-'0') * w1[i]
	}
	for i := 0; i < 11; i++ {
		s2 += int(d[i]-'0') * w2[i]
	}
	return s1%11%10 == int(d[10]-'0') && s2%11%10 == int(d[11]-'0')
}

func snilsValid(s string) bool {
	d := digitsOnly(s)
	if len(d) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
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
	return control == int(d[9]-'0')*10+int(d[10]-'0')
}
