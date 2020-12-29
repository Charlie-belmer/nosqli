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
    "fmt"
)

/**
Attempt to inject control characters into get parameters, searching for different values
**/
func GetInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
    var injectables []scanutil.InjectionObject
    injectables = append(injectables, InjectMongoCharacters(att)...)
    return injectables
}


/*
 * Check to see if a list of injectables already contains a given paramter
 */
func injectablesContainsParam(injectables []scanutil.InjectionObject, param string) bool {
    for _, i := range injectables {
        if i.InjectableParam == param {
            return true
        }
    }
    return false
}

/*
 * Check to see if a list of injectables already contains all the given paramtera
 */
func injectablesContainsParams(injectables []scanutil.InjectionObject, params []string) bool {
    for _, p := range params {
        if injectablesContainsParam(injectables, p) {
            return true
        }
    }
    return false
}

func paramsFromTransform(combination []map[string]string) []string {
    params := make([]string, len(combination))
    for i, valmap := range(combination) {
        params[i] = valmap["oldkey"]
    }
    return params
}

/**
 *  Try to test various get parameter injections, searching for different results.
 *  For instance param=basic might return a different page than param[$lt] basic or 
 *  param[$nin]=basic. 
 *  If it works with one parameter, it likely works with all GET injections.
 */
func InjectMongoCharacters(att scanutil.AttackObject) []scanutil.InjectionObject {
    baseline := att.Copy()
    baselineRes, err := baseline.Send()
    if err != nil {
        fmt.Println(err)
        return nil
    }

    truthyValues := [][]string{ {"[$ne]", ""}, {"[$ne]", "a"} }

    var injectables []scanutil.InjectionObject
/*
    combinations := scanutil.GetTransformedValues(
                        att.QueryParams(),
                        func(s string) string { return s + injection },
                        func(_ string) string { return injectedValue },
                        true,
                        true,
                    )
*/
    keys := scanutil.Keys(att.QueryParams())
    for combo := range scanutil.StringCombinations(keys) {
        for _, injection := range data.MongoGetInjection {
            for _, p := range combo {
                // We have to run the injections once for each truthy value
                for _, truthyInjection := range truthyValues {
                    if injectablesContainsParam(injectables, p) { continue } // don't check params we already caught

                    injectionObj := att.Copy()
                    // Go through all other keys in combo, setting to truthy
                    for _, p2 := range combo {
                        if p2 == p {continue}
                        injectionObj.ReplaceQueryParam(p2, p2 + truthyInjection[0], truthyInjection[1])
                    }
                    for _, injectedValue := range append([]string{"", "a", "z", "0", "9"}, att.QueryParams()[p]) {
                        injectionObj.ReplaceQueryParam(p, p + injection, injectedValue)
                        res, _ := injectionObj.Send()
                        if !baselineRes.ContentEquals(res) {
                            var injectable = scanutil.InjectionObject{
                                Type:            scanutil.GetParam,
                                AttackObject:    injectionObj,
                                InjectableParam: p,
                                InjectedParam:   p + injection,
                                InjectedValue:   injectedValue,
                            }
                            injectables = append(injectables, injectable)
                            // don't keep searching for more injections on this param since we found one:
                            break
                        }
                        injectionObj.ReplaceQueryParam(p + injection, p, injectedValue)
                    }
                }
            }
        }
    }
    return injectables
}


// Try making the generation generic
/*
func InjectMongoCharactersTrial(att scanutil.AttackObject) []scanutil.InjectionObject {
    baseline := att.Copy()
    baselineRes, err := baseline.Send()
    if err != nil {
        fmt.Println(err)
        return nil
    }

    var injectables []scanutil.InjectionObject

    combinations := scanutil.GetTransformedValues(
                        att.QueryParams(),
                        func(s string) string { return s + injection },
                        func(_ string) string { return injectedValue },
                        true,
                        true,
                    )
    for _, combo := range(combinations) {
        params := paramsFromTransform(combo)
        if injectablesContainsParams(injectables, params) {
            continue
        }
        for _, injection := range data.MongoGetInjection {
            for _, injectedValue := range append([]string{"", "a", "z", "0", "9"}, scanutil.Values(params)...) {
                injectionObj := att.Copy()
                injectedParams := ""
                injectedParamNew := ""
                for _, valmap := range(combo) {
                    injectionObj.ReplaceQueryParam(valmap["oldkey"], valmap["newkey"], valmap["newvalue"])
                    injectedParams += valmap["oldkey"] + ","
                    injectedParamNew += valmap["newkey"] + ","
                }
                res, _ := injectionObj.Send()
                if !baselineRes.ContentEquals(res) {
                    for _, p := range params {
                        // add one for each param
                        var injectable = scanutil.InjectionObject{
                            Type:            scanutil.GetParam,
                            AttackObject:    injectionObj,
                            InjectableParam: p,
                            InjectedParam:   injectedParamNew,
                            InjectedValue:   injectedValue,
                        }
                        injectables = append(injectables, injectable)
                    }
                }
            }
        }
    }
    return injectables
}
*/