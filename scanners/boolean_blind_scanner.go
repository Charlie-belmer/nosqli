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
package scanners

import (
	"github.com/Charlie-belmer/nosqli/scanutil"
	//"github.com/Charlie-belmer/nosqli/data"
    "fmt"
)

/** 
Run injection assuming that no errors are being returned.
**/
func BlindBooleanInjectionTest(att scanutil.AttackObject) {
	//always false regex: a^
	//always true regex: .*

	// try running a standard request, a false, and a true, then comparing. 
	// We may at some point need to also do 
	iterateRegexGetBooleanInjections(att)

}

/**
 * For each GET param, see if we can do regex attacks against the param.
 *
 * TODO: does it make sense to also try combinations of parameters?
 *   -> Seems yes, since some params won't show injectable while another param is false. Could
 *      recurse on this function with a list of known injectables, and set each to true.
 */
func iterateRegexGetBooleanInjections(att scanutil.AttackObject) {
	baseline, _ := att.Send()
	trueRegex := `.*`
	falseRegex := `a^`
	foundInjection := false
	for k, v := range att.QueryParams() {
		injectedValue := trueRegex
		injectedKey := k + `[$regex]`
		att.ReplaceQueryParam(k, injectedKey, injectedValue)
		trueRes, _ := att.Send()

		injectedValue = falseRegex
		att.SetQueryParam(injectedKey, injectedValue)
		falseRes, _ := att.Send()
		if baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
			
		} else if baseline.ContentEquals(trueRes) && !baseline.ContentEquals(falseRes) {
			//baseline is true
			if !hasNOSQLError(falseRes.Body) {
				// It's not a different response because of a nosql error message
				foundInjection = true
			}
		} else if !baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
			//baseline is false
			if !hasNOSQLError(falseRes.Body) {
				// It's not a different response because of a nosql error message
				foundInjection = true
			}
		}

		if foundInjection {
			fmt.Println("Found a blind boolean injection:")
			fmt.Printf("  URL: %s\n", att.Request.URL)
			fmt.Printf("  param: %s\n", k)
			fmt.Printf("  Injection: %s=%s\n\n", injectedKey, injectedValue)
		}

		//reset value to default
		att.ReplaceQueryParam(injectedKey, k, v)
	}
}