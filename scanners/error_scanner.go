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
	"github.com/Charlie-belmer/nosqli/data"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"log"
	"regexp"
)

/**
Run injection tests looking for error strings being returned
in the reponse.
**/
func ErrorBasedInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject
	injectables = append(injectables, injectSpecialCharsIntoQuery(att)...)
	injectables = append(injectables, injectSpecialCharsIntoBody(att)...)
	return injectables
}

func hasNOSQLError(body string) bool {
	mongoErrors := searchError(body, data.MongoErrorStrings)
	mongooseErrors := searchError(body, data.MongooseErrorStrings)

	return mongoErrors || mongooseErrors
}

func hasJSError(body string) bool {
	jsErrors := searchError(body, data.JSSyntaxErrorStrings)
	return jsErrors
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
func injectSpecialCharsIntoQuery(att scanutil.AttackObject) []scanutil.InjectionObject {
	i := iterateGetInjections(att, data.MongoSpecialCharacters, false)
	i = append(i, iterateGetInjections(att, data.MongoSpecialKeyCharacters, true)...)
	return i
}

/**
 * Inject characters that can cause webservers to return an error
 * if they are not properly escaping data passed in via
 * POST requests in the body.
 */
func injectSpecialCharsIntoBody(att scanutil.AttackObject) []scanutil.InjectionObject {
	i := iterateBodyInjections(att, data.MongoSpecialCharacters, false)
	i = append(i, iterateBodyInjections(att, data.MongoSpecialKeyCharacters, true)...)
	i = append(i, iterateBodyInjections(att, data.MongoJSONErrorAttacks, true)...)
	return i
}

func iterateBodyInjections(att scanutil.AttackObject, injectionList []string, injectKeys bool) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject
	for _, injection := range injectionList {
		for _, pattern := range att.BodyValues {
			att.ReplaceBodyObject(pattern.Value, injection, injectKeys, pattern.Placement)
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				var injectable = scanutil.InjectionObject{
					Type:            scanutil.Error,
					AttackObject:    att,
					InjectableParam: pattern.Value,
					InjectedParam:   injection,
				}
				injectables = append(injectables, injectable)
			}

			att.RestoreBody() //reset value to default
		}
	}
	return injectables
}

func iterateGetInjections(att scanutil.AttackObject, injectionList []string, injectKeys bool) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject
	for _, injection := range injectionList {
		for k, v := range att.QueryParams() {
			injectedValue := v
			injectedKey := k
			if injectKeys {
				att.ReplaceQueryParam(k, k+injection, v)
				injectedKey = k + injection
			} else {
				att.SetQueryParam(k, injection)
				injectedValue = injection
			}
			res, _ := att.Send()
			if hasNOSQLError(res.Body) {
				var injectable = scanutil.InjectionObject{
					Type:            scanutil.Error,
					AttackObject:    att,
					InjectableParam: k,
					InjectedParam:   injectedKey,
					InjectedValue:   injectedValue,
				}
				injectables = append(injectables, injectable)
			}

			//reset value to default
			if injectKeys {
				att.ReplaceQueryParam(k+injection, k, v)
			} else {
				att.SetQueryParam(k, v)
			}
		}
	}
	return injectables
}
