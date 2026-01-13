package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ScorerConfig holds the configuration for the ThreatScorer.
type ScorerConfig struct {
	// KeywordWeights maps simple keywords/phrases to their risk scores (0.0 - 1.0+)
	KeywordWeights map[string]float64 `yaml:"keyword_weights"`

	// CryptoPatterns maps crypto pattern strings to risk scores
	CryptoPatterns map[string]float64 `yaml:"crypto_patterns"`

	// ToolPoisonPatterns maps regex strings to severity
	ToolPoisonPatterns map[string]float64 `yaml:"tool_poison_patterns"`

	// BenignPatterns maps benign phrases to negative weights (v4.7 Enhancement)
	// These reduce FP on legitimate technical content
	BenignPatterns map[string]float64 `yaml:"benign_patterns"`
}

// Global variable to hold the loaded config
var (
	scorerConfig   *ScorerConfig
	scorerConfigMu sync.RWMutex
)

// defaultKeywordWeights provides hardcoded fallback weights when YAML config is unavailable.
// This ensures heuristic detection always works even without configuration files.
var defaultKeywordWeights = map[string]float64{
	// Instruction override patterns
	"ignor": 0.5, "previous": 0.5, "system": 0.5, "root": 0.6, "evil": 1.5,
	"story": 0.4, "narrative": 0.4,
	"sys": 0.3, "promp": 0.4, "exec": 0.5,
	"anter": 0.3, "rm": 0.5, "rf": 0.5, "shell": 0.5,
	"export": 0.6, "passwords": 0.5,
	"sql": 0.3, "injection": 0.3,
	"grant": 0.6, "access": 0.4,
	// SQL-specific patterns (multi-word)
	"drop table": 0.9, "drop database": 0.9, "truncate table": 0.9,
	"delete from": 0.7, "delete table": 0.8,
	// ASCII art detection
	"potential_ascii_art_injection": 0.8,
	"obfuscation_block_detected":    0.8,
	"forget":                        0.6,
	"disregard":                     0.6,
	// Instruction override patterns (multi-word)
	"ignore instruction": 0.8, "override instruction": 0.8, "disregard instruction": 0.8,
	"forget instruction": 0.8, "bypass instruction": 0.8,
	// System Prompt Extraction
	"repeat everything": 0.8, "repeat all": 0.7, "text above": 0.7,
	// File paths
	"etc/nopasswd": 0.9, "etc/shadow": 0.9, "etc/passwd": 0.9,
	".ssh": 0.8, "id_rsa": 0.8, ".aws": 0.8,
	// Psych keywords
	"urgent": 1.5, "immediately": 1.2, "admin": 0.8, "delete": 1.0,
	"roleplay": 1.5, "pretend": 1.5, "manager": 1.2, "ceo": 1.5,
	"bypass security": 0.8, "security bypass": 0.8, "override security": 0.8,
	"override": 1.2, "ignore": 1.2,
	"context window": 0.7, "what were you told": 0.7,
	"summarize.*instru": 0.7, "output.*instru": 0.7, "encode.*instru": 0.7,
	"first letter of each": 0.6, "debug mode": 0.6, "internal param": 0.7,
	"before you are": 0.7, "what text appears": 0.7, "your hidden": 0.7,
	// Tool Poisoning detection
	"<important>": 0.9, "<hidden>": 0.9, "[hidden]": 0.9,
	"do not mention this": 0.9, "don't tell the user": 0.9,
	"without user knowledge": 0.9, "without telling": 0.8,
	// Markdown exfiltration
	"![": 0.3, "?data=": 0.6, "?secret=": 0.8, "?key=": 0.6,
	"exfil": 0.8, "collect?": 0.7, "/steal?": 0.9,
	// Typo variants
	"ignroe": 0.5, "ingore": 0.5, "iognre": 0.5,
	"sysetm": 0.4, "systme": 0.4, "pormpt": 0.3, "prmotp": 0.3,
	// Multilingual keywords
	"忽略": 0.6, "无视": 0.6, "系统": 0.4, "指令": 0.5, "之前": 0.4, "提示": 0.4,
	"删除": 0.5, "密码": 0.6, "密钥": 0.6, "执行": 0.5,
	"無視": 0.6, "システム": 0.4, "指示": 0.5, "命令": 0.5, "前の": 0.4,
	"削除": 0.5, "パスワード": 0.6, "実行": 0.5,
	"ignorar": 0.5, "ignora": 0.5, "anterior": 0.4, "previo": 0.4,
	"olvida": 0.6, "olvidar": 0.6,
	"sistema": 0.4, "instruccion": 0.5, "contraseña": 0.6, "ejecutar": 0.5, //nolint:misspell // Spanish
	"무시": 0.6, "시스템": 0.4, "지시": 0.5, "이전": 0.4, "비밀번호": 0.6,
	"잊어":    0.6,
	"игнор": 0.5, "систем": 0.4, "пароль": 0.6, "удалить": 0.5,
	"забудь": 0.6, "забей": 0.5, "правила": 0.4,
	"تجاهل": 0.6, "نظام": 0.4, "سابق": 0.4, "انسى": 0.6,
	"अनदेखा": 0.6, "भूल": 0.6,
	"ignorer": 0.5, "oublie": 0.6, "précédent": 0.4,
	"ignorieren": 0.5, "vergiss": 0.6, "vorherigen": 0.4,
	"esquece": 0.6, "esquecer": 0.6,
	// Attack patterns
	"password": 0.4, "api key": 0.5, "api keys": 0.5, "secret key": 0.5,
	"show me the": 0.2, "tell me the": 0.2, "give me the": 0.3,
	"no ethical": 0.7, "without restrictions": 0.7, "no restrictions": 0.7,
	"no longer an ai": 0.8, "you are now": 0.4, "act as": 0.3,
	"no guidelines": 0.7, "without guidelines": 0.7,
	// v5.0: DAN/Jailbreak patterns
	"amoral": 0.9, "completely amoral": 1.2, "immoral ai": 1.0,
	"without any regards": 0.9, "no regards for": 0.9,
	"token system": 0.6, "tokens will be": 0.6, "deducted": 0.4,
	"refuse to answer": 0.5, "reject or refuse": 0.6,
	"answer any request": 0.7, "free of all restrictions": 0.9,
	// v5.0: Data exfiltration patterns
	"training data": 0.6, "fine-tuning": 0.5, "fine tuning": 0.5,
	"chain of thought": 0.5, "internal reasoning": 0.6,
	"model weights": 0.7, "model architecture": 0.6,
	// v5.0: Buried attack markers
	"[system:": 0.8, "[admin:": 0.8, "[hidden instruction": 0.9,
	"for research": 0.3, "academic research": 0.3, "research purposes": 0.3,
	"phishing": 0.6, "malware": 0.6, "exploit": 0.5,
	"please say": 0.3, "pwned": 0.8, "i have been pwned": 0.9,
	"say the following": 0.4,
	"first character":   0.5, "one by one": 0.4, "first letter": 0.4,
	"first half": 0.4, "second half": 0.4,
	"concatenate": 0.4, "combine and": 0.4, "step 1": 0.2, "step 2": 0.2,
	"race and gender": 0.6, "discriminat": 0.5,
	"translation dictionary": 0.5, "use this dictionary": 0.5,
	// CSV Formula Injection
	"=cmd|": 1.5, "=cmd |": 1.5, "=dde|": 1.5, "=dde(": 1.5,
	"=rundll": 1.2, "=rundll32": 1.2, "=msexcel|": 1.2,
	"=powershell": 1.5, "=bash": 1.2, "=sh ": 1.0,
	"@sum(": 0.8, "+sum(": 0.8, "-sum(": 0.8,
	"|cmd": 1.0, "|powershell": 1.0, "!a0": 0.9, "!a1": 0.9,
}

// defaultCryptoPatterns provides hardcoded fallback crypto detection patterns.
var defaultCryptoPatterns = map[string]float64{
	// Private Keys (CRITICAL - instant block)
	"-----BEGIN PRIVATE KEY-----":           50.0,
	"-----BEGIN RSA PRIVATE KEY-----":       50.0,
	"-----BEGIN EC PRIVATE KEY-----":        50.0,
	"-----BEGIN DSA PRIVATE KEY-----":       50.0,
	"-----BEGIN ED25519 PRIVATE KEY-----":   50.0,
	"-----BEGIN OPENSSH PRIVATE KEY-----":   50.0,
	"-----BEGIN ENCRYPTED PRIVATE KEY-----": 50.0,
	"-----BEGIN PGP PRIVATE KEY BLOCK-----": 50.0,
	// SSH Public Keys (HIGH)
	"ssh-rsa ":         40.0,
	"ssh-ed25519 ":     40.0,
	"ecdsa-sha2-nistp": 40.0,
	"ssh-dss ":         40.0,
	// Certificates (MEDIUM)
	"-----BEGIN CERTIFICATE-----":         35.0,
	"-----BEGIN X509 CERTIFICATE-----":    35.0,
	"-----BEGIN CERTIFICATE REQUEST-----": 30.0,
	"-----BEGIN PKCS7-----":               30.0,
	// PGP blocks
	"-----BEGIN PGP PUBLIC KEY BLOCK-----": 25.0,
	"-----BEGIN PGP MESSAGE-----":          20.0,
	"-----BEGIN PGP SIGNATURE-----":        15.0,
	// Partial headers
	"PRIVATE KEY-----": 35.0,
	"-----BEGIN":       15.0,
}

// LoadScorerConfig loads the scorer configuration from a YAML file.
// If the config file doesn't exist, this returns nil (not an error) to allow
// graceful fallback to the hardcoded default weights in GetKeywordWeights().
// This design enables the OSS version to work without any config files.
func LoadScorerConfig(configDir string) error {
	path := filepath.Join(configDir, "scorer_weights.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Intentionally return nil (not error) when config file is missing.
			// This allows fallback to hardcoded defaults in GetKeywordWeights().
			// OSS users shouldn't need to create config files to use the scanner.
			return nil
		}
		return fmt.Errorf("failed to read scorer config file: %w", err)
	}

	var config ScorerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse scorer config: %w", err)
	}

	scorerConfigMu.Lock()
	scorerConfig = &config
	scorerConfigMu.Unlock()

	fmt.Printf("[INFO] Loaded scorer config from %s with %d weights\n", path, len(config.KeywordWeights))
	return nil
}

// ResetScorerConfig resets the global scorer config to nil.
// This is primarily used in tests to ensure a clean state.
func ResetScorerConfig() {
	scorerConfigMu.Lock()
	scorerConfig = nil
	scorerConfigMu.Unlock()
}

// GetKeywordWeights returns the loaded keyword weights.
// Falls back to hardcoded defaults if no YAML config is loaded.
func GetKeywordWeights() map[string]float64 {
	scorerConfigMu.RLock()
	defer scorerConfigMu.RUnlock()

	if scorerConfig != nil && len(scorerConfig.KeywordWeights) > 0 {
		return scorerConfig.KeywordWeights
	}
	return defaultKeywordWeights // Fallback to hardcoded defaults
}

// GetCryptoPatterns returns the loaded crypto pattern weights.
// Falls back to hardcoded defaults if no YAML config is loaded.
func GetCryptoPatterns() map[string]float64 {
	scorerConfigMu.RLock()
	defer scorerConfigMu.RUnlock()

	if scorerConfig != nil && len(scorerConfig.CryptoPatterns) > 0 {
		return scorerConfig.CryptoPatterns
	}
	return defaultCryptoPatterns // Fallback to hardcoded defaults
}

// GetBenignPatterns returns the loaded benign pattern weights (v4.7 Enhancement).
// These are negative weights that reduce scores for legitimate technical phrases.
func GetBenignPatterns() map[string]float64 {
	scorerConfigMu.RLock()
	defer scorerConfigMu.RUnlock()

	if scorerConfig != nil && len(scorerConfig.BenignPatterns) > 0 {
		return scorerConfig.BenignPatterns
	}
	return map[string]float64{} // Return empty if no config loaded
}

// MaxBenignDiscount caps the maximum score reduction from benign patterns.
// This prevents stacking multiple benign patterns from completely zeroing out a score.
// v5.0: Increased from -0.5 to -0.65 to allow truly benign educational queries
// to get below the WARN threshold (0.40)
const MaxBenignDiscount = -0.65

// ApplyBenignPatternDiscount calculates the discount for benign patterns in text.
// Returns the total discount (negative value, capped at MaxBenignDiscount) and matched patterns.
func ApplyBenignPatternDiscount(text string) (float64, []string) {
	benignPatterns := GetBenignPatterns()
	if len(benignPatterns) == 0 {
		return 0, nil
	}

	textLower := strings.ToLower(text)
	discount := 0.0
	var matched []string

	for pattern, weight := range benignPatterns {
		if strings.Contains(textLower, strings.ToLower(pattern)) {
			discount += weight // Weight is already negative
			matched = append(matched, pattern)
		}
	}

	// Cap the discount to prevent excessive score reduction
	if discount < MaxBenignDiscount {
		discount = MaxBenignDiscount
	}

	return discount, matched
}

// domainRelevantKeywords are keywords that have domain-specific benign meanings
// (e.g., "ignore" in .gitignore, "override" in CSS, "delete" in SQL)
var domainRelevantKeywords = map[string]bool{
	"ignore": true, "override": true, "delete": true, "bypass": true,
	"skip": true, "system": true, "execute": true, "disable": true,
	"remove": true, "drop": true, "grant": true, "access": true,
}

// GetMatchedScorerKeywords returns keywords from the scorer config that actually
// matched in the given text. This ensures domain discounts are only applied for
// keywords that actually contributed to the heuristic score.
func GetMatchedScorerKeywords(text string) []string {
	textLower := strings.ToLower(text)
	weights := GetKeywordWeights()

	var matched []string
	seen := make(map[string]bool) // Deduplicate

	for keyword := range weights {
		keywordLower := strings.ToLower(keyword)
		// Only include domain-relevant keywords (not all scorer keywords)
		// Extract the base keyword for multi-word patterns
		baseKeyword := keywordLower
		if idx := strings.Index(keywordLower, " "); idx != -1 {
			baseKeyword = keywordLower[:idx]
		}

		if domainRelevantKeywords[baseKeyword] && strings.Contains(textLower, keywordLower) {
			if !seen[baseKeyword] {
				seen[baseKeyword] = true
				matched = append(matched, baseKeyword)
			}
		}
	}

	return matched
}
