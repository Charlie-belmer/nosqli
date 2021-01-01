/*
Copyright © 2019 Charlie Belmer <Charlie.Belmer@protonmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"log"

	"github.com/Charlie-belmer/nosqli/scanners"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan endpoint for NoSQL Injection vectors",
	Long: `Scan an endpoint for NoSQL Injection vectors. This will return text 
specifying whether an injection was successfully found or not. When passing in 
values, it is important to try to pass in valid default values to maximize findings.
For instance, if you wish to check user/password submissions, try to submit a valid username.

Examples:
    nosqli scan -u http://localhost/page?id=5`,
	Run: func(cmd *cobra.Command, args []string) {
		var scanOptions = scanutil.ScanOptions{target, request, proxy, userAgent, requestData, requireHTTPS}

		attackObj, err := scanutil.NewAttackObject(scanOptions)
		if err != nil {
			log.Fatal(err)
		}

		var injectables []scanutil.InjectionObject
		fmt.Printf("Running Error based scan...\n")
		injectables = append(injectables, scanners.ErrorBasedInjectionTest(attackObj)...)
		fmt.Printf("Running GET parameter scan...\n")
		injectables = append(injectables, scanners.GetInjectionTest(attackObj)...)
		fmt.Printf("Running Boolean based scan...\n")
		injectables = append(injectables, scanners.BlindBooleanInjectionTest(attackObj)...)
		fmt.Printf("Running Timing based scan...\n")
		injectables = append(injectables, scanners.TimingInjectionTest(attackObj)...)
		display(injectables)
	},
}

func display(injectables []scanutil.InjectionObject) {
	for _, in := range injectables {
		in.Print()
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
