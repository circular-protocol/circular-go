package circular_protocol_api

import (
	"fmt"

	"github.com/circular-protocol/circular_go/circular_protocol_api"
)

// Global variables or configurations can be declared here
var (
	Version = circular_protocol_api.GetVersion()
)

// Init function to set up the package
func init() {
	// Example of any initialization logic you want to execute
	fmt.Println("Initializing circular_protocol_api package")

}
