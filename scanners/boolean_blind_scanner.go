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
	"fmt"
	"github.com/Charlie-belmer/nosqli/data"
	"github.com/Charlie-belmer/nosqli/scanutil"
)

/**
Run injection assuming that no errors are being returned, but the page may differ in detectable ways.
**/
func BlindBooleanInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
	i := iterateRegexGetBooleanInjections(att)
	i = append(i, iterateRegexPOSTBooleanInjections(att)...)
	i = append(i, iterateJSGetBooleanInjections(att)...)
	i = append(i, iterateJSPostBooleanInjections(att)...)
	i = append(i, iterateObjectInjections(att)...)
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

// Run and compare the three requests to test for an injection
func runInjection(baseline, trueObject, falseObject scanutil.AttackObject, key, injectedKey, trueVal, falseVal string) (scanutil.InjectionObject, bool) {
	baselineRes, err := baseline.Send()
	if err != nil {
		fmt.Println(err)
	}

	trueRes, err := trueObject.Send()
	if err != nil {
		fmt.Println(err)
	}

	falseRes, err := falseObject.Send()
	if err != nil {
		fmt.Println(err)
	}
	injectable := scanutil.InjectionObject{}
	if isBlindInjectable(baselineRes, trueRes, falseRes) {
		injectable = scanutil.InjectionObject{
			Type:            scanutil.Blind,
			AttackObject:    baseline,
			InjectableParam: key,
			InjectedParam:   injectedKey,
			InjectedValue:   "true: " + trueVal + ", false: " + falseVal,
		}
		return injectable, true
	}
	return injectable, false
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

	baseline := att.Copy()
	baseline2 := att.Copy()
	// Set all to empty keys, and see if we can still get a baseline - this will allow us to get
	// a full injection, unlike something like user=john.*, which might give a baseline of a single
	// record, we would prefer user=.*, though in some cases, we might still need to keep the prefix
	for _, key := range keys {
		baseline2.SetQueryParam(key, "")
	}
	baselineRes2, err := baseline2.Send()
	if err == nil && !hasJSError(baselineRes2.Body) && !hasNOSQLError(baselineRes2.Body) {
		baseline = baseline2
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range scanutil.StringCombinations(keys) {
		//for each combo, we will first set the value of each key to the always true regex
		trueObj := baseline.Copy()
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			trueObj.ReplaceQueryParam(key, injectedKey, trueRegex)
		}

		//Then test each key individually for boolean injection.
		for _, key := range keylist {
			injectedKey := key + `[$regex]`
			falseObj := trueObj.Copy()
			falseObj.SetQueryParam(injectedKey, falseRegex)

			injectable, injectionSuccess := runInjection(baseline, trueObj, falseObj, key, injectedKey, trueRegex, falseRegex)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
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

	baseline := att
	trueRegex := `{"$regex": ".*"}`
	falseRegex := `{"$regex": "a^"}`
	injectKeys := true

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for keylist := range scanutil.BodyItemCombinations(att.BodyValues) {
		trueObj := baseline.Copy()

		//for each combo, we will first set the value of each key to the always true regex
		for _, pattern := range keylist {
			trueObj.ReplaceBodyObject(pattern.Value, trueRegex, injectKeys, pattern.Placement)
		}
		falseObj := trueObj.Copy()
		//Then test each key individually for boolean injection.
		for i, pattern := range keylist {
			falseObj.ReplaceBodyObject(trueRegex, falseRegex, injectKeys, i)

			injectable, injectionSuccess := runInjection(baseline, trueObj, falseObj, pattern.Value, pattern.Value, trueRegex, falseRegex)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
			falseObj.ReplaceBodyObject(falseRegex, trueRegex, injectKeys, -1)
		}
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
	for _, quoteType := range []string{"'", "\""} {
		// try with both single quoted and double quoted strings
		injections := scanutil.JSInjections(quoteType)
		for keylist := range scanutil.StringCombinations(keys) {
			for trueJS, falseInjections := range injections {
				// Assign all keys in this combination to True
				trueObj := att.Copy()
				for _, key := range keylist {
					trueObj.SetQueryParam(key, original_params[key]+trueJS)
				}

				falseObj := trueObj.Copy()
				for _, key := range keylist {
					for _, falseJS := range falseInjections {
						injection := original_params[key] + falseJS
						falseObj.SetQueryParam(key, injection)
						injectable, injectionSuccess := runInjection(att, trueObj, falseObj, key, key, original_params[key]+trueJS, injection)
						if injectionSuccess {
							injectables = append(injectables, injectable)
						}
						falseObj.SetQueryParam(key, original_params[key])
					}

				}
			}
		}
	}
	return scanutil.Unique(injectables)
}

func iterateJSPostBooleanInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of
	 *  parameters to maximize injection findings.
	 */
	for _, quoteType := range []string{"'"} {
		// try with both single quoted and double quoted strings
		injections := scanutil.JSInjections(quoteType)
		for keylist := range scanutil.BodyItemCombinations(att.BodyValues) {
			for trueJS, falseInjections := range injections {
				// Assign all keys in this combination to True

				trueObj := att.Copy()
				for _, key := range keylist {
					injection := `"` + key.Value + trueJS + `"`
					trueObj.ReplaceBodyObject(key.Value, injection, false, key.Placement)
				}
				
				for i, key := range keylist {
					for _, falseJS := range falseInjections {
						falseObj := trueObj.Copy()
						injection := `"` + key.Value + falseJS + `"`
						falseObj.ReplaceBodyObject(key.Value + trueJS, injection, false, i)
						injectable, injectionSuccess := runInjection(att, trueObj, falseObj, key.Value, key.Value, key.Value+trueJS, injection)
						if injectionSuccess {
							injectables = append(injectables, injectable)
						}
					}
				}
			}
		}
	}
	return scanutil.Unique(injectables)
}

/*****************************************************
				Object injections
******************************************************/

/**
 * Sometimes, an application passes a full object back, which is placed directly into the backend. Let's see if we can detect that.
 */

func iterateObjectInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	var injectables []scanutil.InjectionObject

	trueRequest := att.Copy()
	falseRequest := att.Copy()
	for _, trueObject := range data.ObjectInjectionsTrue {
		trueRequest.SetBody(trueObject)
		for _, falseObject := range data.ObjectInjectionsFalse {
			falseRequest.SetBody(falseObject)
			injectable, injectionSuccess := runInjection(att, trueRequest, falseRequest, "Body", "", trueObject, falseObject)
			if injectionSuccess {
				injectables = append(injectables, injectable)
			}
		}
	}
	return scanutil.Unique(injectables)
}
