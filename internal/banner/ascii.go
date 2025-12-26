package banner

import (
	"fmt"
)

const banner = `
                 _ _                         _
                | (_)                       | |
  _ __  ___  __| |_  __ _ _   _ _ __   ___ | |__
 | '_ \/ __|/ _' | |/ _' | | | | '_ \ / __|| '_ \
 | | | \__ \ (_| | | (_| | |_| | |_) |\__ \| | | |
 |_| |_|___/\__,_|_|\__, |\__,_| .__(_)___/|_| |_|
                     __/ |     | |
                    |___/      |_|
`

func PrintAsciBanner() {
	fmt.Printf("%s\n", banner)
}

func GetAsciBanner() string {
	return banner
}
