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
    //"fmt"
)

/** 
Run injection assuming that no errors are being returned.
**/
func BlindBooleanInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
	//always false regex: a^
	//always true regex: .*

	// try running a standard request, a false, and a true, then comparing. 
	// We may at some point need to also do 
	i := iterateRegexGetBooleanInjections(att)
	i = append(i, iterateRegexPOSTBooleanInjections(att)...)
	return i
}

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

	baseline, _ := att.Send()
	trueRegex := `.*`
	falseRegex := `a^`

	original_params := att.QueryParams()
	keys := make([]string, len(original_params))

	// Get list of keys
	for k, _ := range original_params {
		keys = append(keys, k)
	}

	/**
	 *	Some apps will have multiple parameters that interact.
	 *  so we need to ensure that we try every combination of 
	 *  parameters to maximize injection findings.
	 */
	for keylist := range(scanutil.Combinations(keys)) {

		//for each combo, we will first set the value of each key to the always true regex
		for _, key := range(keylist) {
			injectedKey := key + `[$regex]`
			att.ReplaceQueryParam(key, injectedKey, trueRegex)
		}

		//Then test each key individually for boolean injection. 
		for _, key := range(keylist) {
			injectedKey := key + `[$regex]`
			trueRes, _ := att.Send()
			att.SetQueryParam(injectedKey, falseRegex)
			falseRes, _ := att.Send()

			if !(baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes)) &&
			  baseline.ContentEquals(trueRes) && !baseline.ContentEquals(falseRes) ||
			  !baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) &&
			  !hasNOSQLError(falseRes.Body) && !hasNOSQLError(trueRes.Body) {
			  	var injectable = scanutil.InjectionObject{
					Type: scanutil.Blind, 
					AttackObject: att,
					InjectableParam: key,
					InjectedParam: injectedKey,
					InjectedValue: falseRegex,
				}
				injectables =  append(injectables, injectable)
			}

			att.SetQueryParam(injectedKey, trueRegex)
		}

		//return the request to the original state.
		for _, key := range(keylist) {
			injectedKey := key + `[$regex]`
			att.ReplaceQueryParam(injectedKey, key, original_params[key])
		}
	}
	return scanutil.Unique(injectables)
}


/**
 * For each POST param, see if we can do regex attacks against the param.
 * See GET injection tests for more commentary on methodology.

 TODO / PROBLEM: the replace just replaces everything - all trues to false and vice versa.
 Instead, it needs to replace just ONE in order... Not sure how to accopmlish this exactly. Possibly
 some combo of re.split with the replaceall
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
	for keylist := range(scanutil.Combinations(att.BodyValues)) {

		//for each combo, we will first set the value of each key to the always true regex
		for _, pattern := range(keylist) {
			att.ReplaceBodyObject(pattern, trueRegex, injectKeys, -1)
		}
		trueRes, _ := att.Send()

		//Then test each key individually for boolean injection. 
		for i, pattern := range(keylist) {
			
			att.ReplaceBodyObject(trueRegex, falseRegex, injectKeys, i)
			falseRes, _ := att.Send()

			if !(baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes)) &&
			  baseline.ContentEquals(trueRes) && !baseline.ContentEquals(falseRes) ||
			  !baseline.ContentEquals(trueRes) && baseline.ContentEquals(falseRes) &&
			  !hasNOSQLError(falseRes.Body) && !hasNOSQLError(trueRes.Body) {
			  	var injectable = scanutil.InjectionObject{
					Type: scanutil.Blind, 
					AttackObject: att,
					InjectableParam: pattern,
					InjectedParam: falseRegex,
				}
				injectables =  append(injectables, injectable)
			}

			att.ReplaceBodyObject(falseRegex, trueRegex, injectKeys, -1)
		}

		//return the request to the original state.
		att.RestoreBody()
	}
	return scanutil.Unique(injectables)
}