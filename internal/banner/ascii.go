package banner

import (
	"strings"
)

func Generate(text string) string {
	text = strings.ToUpper(text)
	return generateASCII(text)
}

func generateASCII(text string) string {
	if text == "" {
		return ""
	}

	// Character map using simple ASCII characters with consistent 4-char width
	charMap := map[rune][]string{
		'A': {
			" /\\ ",
			"|__|",
			"|  |",
		},
		'B': {
			"|-- ",
			"|--\\",
			"|__/",
		},
		'C': {
			"/---",
			"|   ",
			"\\___",
		},
		'D': {
			"|--\\",
			"|  |",
			"|__/",
		},
		'E': {
			"|___",
			"|-- ",
			"|___",
		},
		'F': {
			"|___",
			"|-- ",
			"|   ",
		},
		'G': {
			"/---",
			"| _|",
			"\\__|",
		},
		'H': {
			"|  |",
			"|__|",
			"|  |",
		},
		'I': {
			"||||",
			" || ",
			"||||",
		},
		'J': {
			"   |",
			"   |",
			"\\__|",
		},
		'K': {
			"|  /",
			"|-< ",
			"|  \\",
		},
		'L': {
			"|   ",
			"|   ",
			"|___",
		},
		'M': {
			"|\\/|",
			"|  |",
			"|  |",
		},
		'N': {
			"|\\  |",
			"| \\ |",
			"|  \\|",
		},
		'O': {
			"/--\\",
			"|  |",
			"\\__/",
		},
		'P': {
			"|--\\",
			"|__/",
			"|   ",
		},
		'Q': {
			"/--\\",
			"|  |",
			"\\__/|",
		},
		'R': {
			"|--\\",
			"|__/",
			"|  \\",
		},
		'S': {
			"/___",
			"\\__ ",
			"___/",
		},
		'T': {
			"||||",
			" || ",
			" || ",
		},
		'U': {
			"|  |",
			"|  |",
			"\\__/",
		},
		'V': {
			"|  |",
			"|  |",
			" \\/ ",
		},
		'W': {
			"|  |",
			"|/\\|",
			"|  |",
		},
		'X': {
			"\\  /",
			" ><",
			"/  \\",
		},
		'Y': {
			"|  |",
			" \\/ ",
			" || ",
		},
		'Z': {
			"||||",
			" // ",
			"||||",
		},
		' ': {
			"    ",
			"    ",
			"    ",
		},
		'.': {
			"    ",
			"    ",
			" .  ",
		},
		'-': {
			"    ",
			"----",
			"    ",
		},
	}

	lines := []string{"", "", ""}

	for _, char := range text {
		if patterns, exists := charMap[char]; exists {
			for i, pattern := range patterns {
				lines[i] += pattern
			}
		} else {
			// Unknown character, use placeholder
			for i := 0; i < 3; i++ {
				lines[i] += "  ?  "
			}
		}
	}

	return strings.Join(lines, "\n")
}
