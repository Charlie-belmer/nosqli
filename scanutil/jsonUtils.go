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
package scanutil

/**
 * Because extracting and inserting attack strings into JSON bodies
 * is a little more complicated.
 */

import (
	"encoding/json"
	"github.com/buger/jsonparser"
)

func isJSON(s string) bool {
	var js map[string]interface{}
	err := json.Unmarshal([]byte(s), &js)
	return err == nil
}

func jsonArrayHandler(arrayData []byte, flattenedSlice []string) []string {
	jsonparser.ArrayEach(arrayData, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		flattenedSlice = append(flattenedSlice, string(value))
		switch dataType.String() {
		case "object":
			flattenedSlice = jsonObjectHandler([]byte(string(value)), flattenedSlice)
		case "array":
			flattenedSlice = jsonArrayHandler(value, flattenedSlice)
		}
	})
	return flattenedSlice
}

func jsonObjectHandler(jsonData []byte, flattenedSlice []string) []string {
	jsonparser.ObjectEach(jsonData, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		flattenedSlice = append(flattenedSlice, string(key))
		flattenedSlice = append(flattenedSlice, string(value))

		switch dataType.String() {
		case "object":
			flattenedSlice = jsonObjectHandler(value, flattenedSlice)
		case "array":
			flattenedSlice = jsonArrayHandler(value, flattenedSlice)
		}
		return nil
	})
	return flattenedSlice
}

/*
 * Takes a JSON object (as a string), and returns all keys and values in a string slice
 */
func FlattenJSON(jsonData string) []string {
	b := []byte(jsonData)
	var s []string
	return jsonObjectHandler(b, s)
}

/*
 * Returns the type of object contained in the string. Could be any of the following
 * 	string
 *	number
 *	object
 *	array
 *	boolean
 *	null
 */
func jsonType(jsonData string) string {
	b := []byte(jsonData)
	_, vtype, _, err := jsonparser.Get(b)
	if err != nil || vtype.String() == "unknown" {
		return "string"
	} else {
		return vtype.String()
	}
}
