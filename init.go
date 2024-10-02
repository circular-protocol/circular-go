package circular_go

import (
	"fmt"
)

// Global variables or configurations can be declared here
var (
	ApiVersion = "1.0.8"
)

// Init function to set up the package
func init() {
	// Example of any initialization logic you want to execute
	fmt.Println("Initializing Circular Protocol API, version:", ApiVersion)
}
