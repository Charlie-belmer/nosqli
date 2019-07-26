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
	"github.com/Charlie-belmer/nosqli/data"
	"regexp"
    "fmt"
    "log"
)

/** 
Run injection tests looking for error strings being returned
in the reponse.
**/
func ErrorBasedInjectionTest(att scanutil.AttackObject) {
	//att := scanutil.NewAttackObject(url)
	injectSpecialCharsIntoQuery(att)
	injectSpecialCharsIntoBody(att)
}

func hasNOSQLError(body string) bool {
	mongoErrors := searchError(body, data.MongoErrorStrings)
	mongooseErrors := searchError(body, data.MongooseErrorStrings) 
	
	return mongoErrors || mongooseErrors
}


func searchError(body string, errorList []string) bool {
	for _, pattern := range errorList {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
	        log.Fatal(err)
	    }
		if matched {
			return true
		}
	}
	return false
}

/** 
 * Inject characters that can cause webservers to return an error
 * if they are not properly escaping data passed in via
 * GET requests.
 */
func injectSpecialCharsIntoQuery(att scanutil.AttackObject) {
	iterateGetInjections(att, data.MongoSpecialCharacters, false)
	iterateGetInjections(att, data.MongoSpecialKeyCharacters, true)
}

/** 
 * Inject characters that can cause webservers to return an error
 * if they are not properly escaping data passed in via
 * POST requests in the body.
 */
func injectSpecialCharsIntoBody(att scanutil.AttackObject) {
	iterateBodyInjections(att, data.MongoSpecialCharacters, false)
	iterateBodyInjections(att, data.MongoSpecialKeyCharacters, true)
	iterateBodyInjections(att, data.MongoJSONErrorAttacks, true)
}

func iterateBodyInjections(att scanutil.AttackObject, injectionList []string, injectKeys bool) {
	for _, injection := range injectionList {
		for _, pattern := range att.BodyValues {
			att.ReplaceBodyObject(pattern, injection, injectKeys)
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				fmt.Println("Matched a probable NoSQL Injection Error (Based on error message):")
				fmt.Printf("  URL: %s\n", att.Request.URL)
				fmt.Printf("  body: %s\n\n", att.Body)
			}

			att.RestoreBody()	//reset value to default
		}
	}
}

func iterateGetInjections(att scanutil.AttackObject, injectionList []string, injectKeys bool) {
	for _, injection := range injectionList {
		for k, v := range att.QueryParams() {
			injectedValue := v
			injectedKey := k
			if injectKeys {
				att.ReplaceQueryParam(k, k + injection, v)
				injectedKey = k + injection
			} else {
				att.SetQueryParam(k, injection)
				injectedValue = injection
			}
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				fmt.Println("Matched a probable NoSQL Injection Error (Based on error message):")
				fmt.Printf("  URL: %s\n", att.Request.URL)
				fmt.Printf("  param: %s\n", k)
				fmt.Printf("  Injection: %s=%s\n\n", injectedKey, injectedValue)
			}

			//reset value to default
			if injectKeys {
				att.ReplaceQueryParam(k + injection, k, v)
			} else {
				att.SetQueryParam(k, v)
			}
		}
	}
}