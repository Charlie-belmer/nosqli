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
	"time"
	"fmt"
	"github.com/Charlie-belmer/nosqli/data"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"github.com/montanaflynn/stats"
)

var sleepTimeMS int = 500

/**
Timing injections are based on the idea that different values injected don't change output in any discernable way.
We can inject commands to try to lengthen the time it takes to respond to a command, and measure the response time.
**/
func TimingInjectionTest(att scanutil.AttackObject) []scanutil.InjectionObject {
	att.IgnoreCache = true  // Ensure we catch all instances of timing attacks
	i := iterateTimingGetInjections(att)
	i = append(i, iteratePostTimingInjections(att)...)
	i = append(i, iteratePostObjectInections(att)...)
	att.IgnoreCache = false // return to default
	return i
}

/*
 *	Make the request in the object, and return the time it took in milliseconds
 */
func measureRequest(request scanutil.AttackObject) float64 {
	start := time.Now()
	_, err := request.Send()
	if err != nil {
		fmt.Printf("Error sending request: %+v\n", err)
	}
	d := time.Since(start)
	return d.Seconds()
}

func baseline(att scanutil.AttackObject) []float64 {
	var baselineTimes []float64

	for i := 0; i < 3; i++ {
		baselineTimes = append(baselineTimes, measureRequest(att))
	}
	return baselineTimes
}

func isTimingInjectable(baselines []float64, injectionTime float64) bool {
	data := stats.LoadRawData(baselines)
	mean, _ := stats.Mean(data)
	stdDev, _ := stats.StdDevS(data)

	if injectionTime > (float64(sleepTimeMS)/1000) && injectionTime > (mean+2*stdDev) {
		return true
	}
	return false
}

func iterateTimingGetInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	baselineTimes := baseline(att)
	var injectables []scanutil.InjectionObject
	params := att.QueryParams()

	for key := range params {
		for _, prefix := range data.JSPrefixes {
			for _, suffix := range data.JSSuffixes {
				for _, tInjection := range data.JSTimingStrings(data.JSTimingStringsRaw, sleepTimeMS) {
					for _, keepVal := range []string{"", params[key]} {
						attackObj := att.Copy()
						attackString := keepVal + prefix + tInjection + suffix
						attackObj.SetQueryParam(key, attackString)
						timing := measureRequest(attackObj)
						if isTimingInjectable(baselineTimes, timing) {
							injectable := scanutil.InjectionObject{
								Type:            scanutil.Timed,
								AttackObject:    attackObj,
								InjectableParam: key,
								InjectedParam:   keepVal,
								InjectedValue:   attackString,
							}
							injectables = append(injectables, injectable)
						}
					}
				}
			}
		}
	}
	return scanutil.Unique(injectables)
}

func iteratePostTimingInjections(att scanutil.AttackObject) []scanutil.InjectionObject {
	baselineTimes := baseline(att)
	var injectables []scanutil.InjectionObject

	for _, bodyValue := range att.BodyValues {
		for _, prefix := range data.JSPrefixes {
			for _, suffix := range data.JSSuffixes {
				for _, tInjection := range data.JSTimingStrings(data.JSTimingStringsRaw, sleepTimeMS) {
					for _, keepVal := range []string{"", bodyValue.Value} {
						for _, wrapQuote := range []string{"", "\""} {
							attackObj := att.Copy()
							attackString := wrapQuote + keepVal + prefix + tInjection + suffix + wrapQuote
							attackObj.ReplaceBodyObject(bodyValue.Value, attackString, false, bodyValue.Placement)
							timing := measureRequest(attackObj)
							if isTimingInjectable(baselineTimes, timing) {
								fmt.Println("Injection Found")
								injectable := scanutil.InjectionObject{
									Type:            scanutil.Timed,
									AttackObject:    attackObj,
									InjectableParam: bodyValue.Value,
									InjectedParam:   bodyValue.Value,
									InjectedValue:   attackString,
								}
								injectables = append(injectables, injectable)
							}
						}
					}
				}
			}
		}
	}

	return scanutil.Unique(injectables)
}

func iteratePostObjectInections(att scanutil.AttackObject) []scanutil.InjectionObject {
	baselineTimes := baseline(att)
	var injectables []scanutil.InjectionObject

	timedRequest := att.Copy()
	for _, tInjection := range data.JSTimingStrings(data.JSTimingObjectInjectionsRaw, sleepTimeMS) {
		timedRequest.SetBody(tInjection)
		timing := measureRequest(timedRequest)
		if isTimingInjectable(baselineTimes, timing) {
			injectable := scanutil.InjectionObject{
				Type:            scanutil.Timed,
				AttackObject:    timedRequest,
				InjectableParam: "Whole Body",
				InjectedParam:   "Whole Body",
				InjectedValue:   tInjection,
			}
			injectables = append(injectables, injectable)
		}
	}
	return scanutil.Unique(injectables)
}
