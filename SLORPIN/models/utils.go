package models

import (
	"encoding/base64"
	"html/template"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday/v2"
)

func (t UserData) IsValid() bool {
	return t.Name != ""
}

func RenderMarkdown(text string) template.HTML {
	unsafe := blackfriday.Run([]byte(text), blackfriday.WithExtensions(blackfriday.HardLineBreak))
	html := bluemonday.UGCPolicy().SanitizeBytes(unsafe)
	return template.HTML(string(html))
}

func Base64Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func RemovePeriods(input string) string {
	return strings.ReplaceAll(input, ".", "")
}
