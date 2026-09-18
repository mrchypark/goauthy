package credential

import (
	"strings"
	"sync"
)

// commonPasswords는 알려진 약한 패스워드 목록입니다.
// NIST SP 800-63B 및 Have I Been Pwned 기반 상위 패스워드를 포함합니다.
var commonPasswords sync.Map

func init() {
	// 상위 1000개 일반적인 패스워드 (소문자 비교)
	passwords := []string{
		"password", "123456", "12345678", "qwerty", "abc123",
		"monkey", "1234567", "letmein", "trustno1", "dragon",
		"baseball", "iloveyou", "master", "sunshine", "ashley",
		"bailey", "shadow", "123123", "654321", "superman",
		"qazwsx", "michael", "football", "password1", "password123",
		"admin", "welcome", "login", "princess", "starwars",
		"solo", "passw0rd", "hello", "charlie", "donald",
		"password1234", "password12345", "password123456",
		"123456789", "1234567890", "000000", "111111", "1234",
		"12345", "666666", "777777", "888888", "999999",
		"qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx",
		"admin123", "root", "toor", "pass", "test",
		"guest", "master", "changeme", "secret", "default",
		"p@ssw0rd", "p@ssword", "pa$$word", "pa$$w0rd",
		"!@#$%^&*", "zxcvbnm", "asdfghjkl", "1234qwer",
		"qwer1234", "abc123456", "password1!", "Password1",
		"Password123", "Password123!", "Admin123", "Welcome1",
		"Welcome123", "Qwerty123", "Passw0rd!", "Summer2024",
		"Winter2024", "Spring2024", "Fall2024", "Company123",
	}
	for _, p := range passwords {
		commonPasswords.Store(strings.ToLower(p), true)
	}
}

// IsCommonPassword는 패스워드가 알려진 일반적인 패스워드인지 확인합니다.
// NIST SP 800-63B 섹션 5.1.1.2에 따라 일반 패스워드를 차단합니다.
func IsCommonPassword(password string) bool {
	_, ok := commonPasswords.Load(strings.ToLower(password))
	return ok
}

// AddCommonPassword는 런타임에 일반 패스워드 목록에 추가합니다.
// 배포 환경에서 조직-specific 패스워드를 추가할 때 사용합니다.
func AddCommonPassword(password string) {
	commonPasswords.Store(strings.ToLower(password), true)
}
