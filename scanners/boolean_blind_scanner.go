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
	"fmt"
)

/**
Run injection assuming that no errors are being returned.
**/
func BlindBooleanInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
	i := iterateRegexGetBooleanInjections(att)
	i = append(i, iterateRegexPOSTBooleanInjections(att)...)
	i = append(i, iterateJSGetBooleanInjections(att)...)
	i = append(i, iterateJSPostBooleanInjections(att)...)
	return i
}

func isBlindInjectable(baseline, trueRes, falseRes scanutil.HTTPResponseObject) bool {
	if hasNOSQLError(falseRes.Body) || hasNOSQLError(trueRes.Body) {
		// Error response, which might indicate injection, but should be caught by error scanner
		return false
	}
	if hasJSError(falseRes.Body) || hasJSError(trueRes.Body) {
		// JS error response - we probably have JS injection, but haven't found a proper boolean 
		// test string yet.
		return false
	}
	if baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
		// no difference in responses
		return false
	}
	if baseline.ContentEquals(trueRes) && !baseline.ContentEquals(falseRes) {
		return true
	}
	if !baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) {
		return true
	}
	return false
}

/*****************************************************
				Mongo REGEX injections
******************************************************/

/**
 * For each GET param, see if we can do regex attacks against the param.
 *
 * Applications may have multiple paramters that interact, such as
 * test.com/type=product&id=58
 *
 * in this case, leaving id as 58 and trying to inject on type likely won't
 * show any results. Instead, we need to set ID to true, and then see if
 * we can inject on type. When we extract data using a blind method,
 * handling each injectable parameter as linked to the others helps us
 * derive tables.
 */
func iterateRegexGetBooleanInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	trueRegex := `.*`
	falseRegex := `a^`

	original_params := att.QueryParams()
	keys := make([]string, 0)

	// Get list of keys
	for k, _ := range original_params {
		keys = append(keys, k)
	}

	baseline, _ := att.Send()
	// Set all to empty keys, and see if we can still get a baseline - this will allow us to get 
	// a full injection, unlike something like user=john.*, which might give a baseline of a single 
	// record, we would prefer user=.*, though in some cases, we might still need to keep the prefix
	for _, key := range keys {
		att.SetQueryParam(key, "")
	}
	baseline2, err := att.Send()
	if err == nil && !hasJSError(baseline2.Body) && !hasNOSQLError(baseline2.Body) {
		baseline = baseline2
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range scanutil.StringCombinations(keys) {
		//for each combo, we will first set the value of each key to the always true regex
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			att.ReplaceQueryParam(key, injectedKey, trueRegex)
		}
		trueRes, _ := att.Send()
		//Then test each key individually for boolean injection.
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			att.SetQueryParam(injectedKey, falseRegex)
			falseRes, _ := att.Send()

			if isBlindInjectable(baseline, trueRes, falseRes) {
				var injectable = scanutil.InjectionObject{
					Type:            scanutil.Blind,
					AttackObject:    att,
					InjectableParam: key,
					InjectedParam:   injectedKey,
					InjectedValue:   "true: " + trueRegex + ", false: " + falseRegex,
				}
				injectables = append(injectables, injectable)
			}

			att.SetQueryParam(injectedKey, trueRegex)
		}

		//return the request to the original state.
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			att.ReplaceQueryParam(injectedKey, key, original_params[key])
		}
	}
	return scanutil.Unique(injectables)
}

/**
* For each POST param, see if we can do regex attacks against the param.
* See GET injection tests for more commentary on methodology.
*/
func iterateRegexPOSTBooleanInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	baseline, _ := att.Send()
	trueRegex := `{"$regex": ".*"}`
	falseRegex := `{"$regex": "a^"}`
	injectKeys := true

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range scanutil.BodyItemCombinations(att.BodyValues) {

		//for each combo, we will first set the value of each key to the always true regex
		for _, pattern := range keylist {
			att.ReplaceBodyObject(pattern.Value, trueRegex, injectKeys, pattern.Placement)
		}
		trueRes, _ := att.Send()

		//Then test each key individually for boolean injection.
		for i, pattern := range keylist {

			att.ReplaceBodyObject(trueRegex, falseRegex, injectKeys, i)
			falseRes, _ := att.Send()

			if isBlindInjectable(baseline, trueRes, falseRes) {
				var injectable = scanutil.InjectionObject{
					Type:            scanutil.Blind,
					AttackObject:    att,
					InjectableParam: pattern.Value,
					InjectedParam:   "true: " + trueRegex + ", false: " + falseRegex,
				}
				injectables = append(injectables, injectable)
			}

			att.ReplaceBodyObject(falseRegex, trueRegex, injectKeys, -1)
		}

		//return the request to the original state.
		att.RestoreBody()
	}
	return scanutil.Unique(injectables)
}

/*****************************************************
				JavaScript injections
******************************************************/


/**
 * For each GET param, see if we can do regex attacks against the param.
 *
 * Applications may have multiple paramters that interact, such as
 * test.com/type=product&id=58
 *
 * in this case, leaving id as 58 and trying to inject on type likely won't
 * show any results. Instead, we need to set ID to true, and then see if
 * we can inject on type. When we extract data using a blind method,
 * handling each injectable parameter as linked to the others helps us
 * derive tables.
 */
func iterateJSGetBooleanInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	baseline, _ := att.Send()

	original_params := att.QueryParams()
	keys := make([]string, 0)

	// Get list of keys
	for k, _ := range original_params {
		keys = append(keys, k)
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	requestCache := map[string]scanutil.HTTPResponseObject{}
	for _, quoteType := range([]string{"'","\""}) {
		// try with both single quoted and double quoted strings
		injections := scanutil.JSInjections(quoteType)
		for keylist := range scanutil.StringCombinations(keys) {
			for trueJS, falseInjections := range(injections) {
				// Assign all keys in this combination to True
				for _, key := range keylist {
					att.SetQueryParam(key, original_params[key] + trueJS)
				}
				trueRes, _ := att.Send()

				for _, key := range keylist {
					for _, falseJS := range(falseInjections) {
						injection := original_params[key] + falseJS
						att.SetQueryParam(key, injection)
						var falseRes scanutil.HTTPResponseObject
						if res, ok := requestCache[att.QueryString()]; !ok{
							var err error
							falseRes, err = att.Send()
							if err != nil {
								fmt.Println(err)
							}
							requestCache[att.QueryString()] = falseRes
						} else {
							falseRes = res
						}

						if isBlindInjectable(baseline, trueRes, falseRes) {
							
							var injectable = scanutil.InjectionObject{
								Type:            scanutil.Blind,
								AttackObject:    att,
								InjectableParam: key,
								InjectedParam:   key,
								InjectedValue:   "true: " + original_params[key] + trueJS + ", false: " + injection,
							}
							injectables = append(injectables, injectable)
						}
					}

					att.SetQueryParam(key, original_params[key] + trueJS)
				}

				//return the request to the original state.
				for _, key := range keylist {
					att.SetQueryParam(key, original_params[key])
				}
			}
		}
	}
	return scanutil.Unique(injectables)
}


func iterateJSPostBooleanInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	baseline, _ := att.Send()

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	requestCache := map[string]scanutil.HTTPResponseObject{}
	for _, quoteType := range([]string{"'","\""}) {
		// try with both single quoted and double quoted strings
		injections := scanutil.JSInjections(quoteType)
		for keylist := range scanutil.BodyItemCombinations(att.BodyValues) {
			for trueJS, falseInjections := range(injections) {
				// Assign all keys in this combination to True
				for _, key := range keylist {
					injection := `"` + key.Value + trueJS + `"`
					att.ReplaceBodyObject(key.Value, injection, false, key.Placement)
				}
				trueRes, _ := att.Send()

				for i, key := range keylist {
					for _, falseJS := range(falseInjections) {
						injection := `"` + key.Value + falseJS + `"`
						att.ReplaceBodyObject(key.Value + trueJS, injection, false, i)
						var falseRes scanutil.HTTPResponseObject
						if res, ok := requestCache[att.Body]; !ok{
							var err error
							falseRes, err = att.Send()
							if err != nil {
								fmt.Println(err)
							}
							requestCache[att.Body] = falseRes
						} else {
							falseRes = res
						}

						if isBlindInjectable(baseline, trueRes, falseRes) {
							
							var injectable = scanutil.InjectionObject{
								Type:            scanutil.Blind,
								AttackObject:    att,
								InjectableParam: key.Value,
								InjectedParam:   key.Value,
								InjectedValue:   "true: " + key.Value + trueJS + ", false: " + injection,
							}
							injectables = append(injectables, injectable)
						}
						att.ReplaceBodyObject(injection, trueJS, false, -1)
					}

					
				}

				//return the request to the original state.
				att.RestoreBody()
			}
		}
	}
		return scanutil.Unique(injectables)
}

