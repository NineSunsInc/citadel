package ml

import "golang.org/x/text/unicode/norm"

// NormalizeUnicode applies NFKC normalization to convert
// mathematical/stylistic Unicode variants to ASCII equivalents
//
// Examples:
//
//	𝐈𝐠𝐧𝐨𝐫𝐞 → Ignore (mathematical bold)
//	Ｉｇｎｏｒｅ → Ignore (fullwidth)
//	ⓘⓖⓝⓞⓡⓔ → ignore (circled)
func NormalizeUnicode(text string) (normalized string, wasNormalized bool) {
	normalized = norm.NFKC.String(text)
	wasNormalized = normalized != text
	return
}
