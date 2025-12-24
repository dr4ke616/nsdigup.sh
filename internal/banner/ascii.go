package banner

import (
	"fmt"
)

const banner = `
       _               _              _     
      | |             | |            | |    
   ___| |__   ___  ___| | _____   ___| |__  
  / __| '_ \ / _ \/ __| |/ / __| / __| '_ \ 
 | (__| | | |  __/ (__|   <\__ \_\__ \ | | |
  \___|_| |_|\___|\___|_|\_\___(_)___/_| |_|                                            
`

func PrintAsciBanner() {
	fmt.Printf("%s\n", banner)
}

func GetAsciBanner() string {
	return banner
}
