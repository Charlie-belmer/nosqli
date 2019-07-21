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
	for _, character := range data.MongoSpecialCharacters {
		for k, v := range att.QueryParams() {
			att.SetQueryParam(k, character)
			res, _ := att.Send()
			searchErrors(res.Body)
			att.SetQueryParam(k, v)	//reset value to default
		}
	}
	//att.SetBodyParam()
	att.Send()

}

func searchErrors(body string) {
	for _, pattern := range data.MongoErrorStrings {
		matched, err := regexp.MatchString(pattern, body)
		if err != nil {
	        log.Fatal(err)
	    }
		if matched {
			fmt.Println("Matched a probable NoSQL Injection Error!\n")
			return
		}
	}
}
