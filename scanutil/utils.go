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

import (
	"github.com/Charlie-belmer/nosqli/data"
	"strings"
)

/* Return all keys for a given map */
func Keys(aMap map[string]string) []string {
	keys := make([]string, len(aMap))
	i := 0
	for k, _ := range aMap {
		keys[i] = k
		i++
	}
	return keys
}

/* Return all values for a given map */
func Values(aMap map[string]string) []string {
	values := make([]string, len(aMap))
	i := 0
	for _, v := range aMap {
		values[i] = v
		i++
	}
	return values
}

/*
 * Transform key:value pairs (generally for parameters) based on passed in transforms.
 * For instance, a site might have something like url/page?user=name, and we could pass
 * this function the key value pair {user:name} with transform functions that would 
 * inject some data.
 *
 * TODO: Get this more generic so it can work on more use cases. Right now func is not in use.
 * 
 * The function returns all combinations of transformed keys and values, with each entry having the following format:
 * 		{"newkey":"transformed_key", "newvalue":"transformed_value", "oldkey":"original_key", "oldvalue":"original_value"}
 *
 * A combination might look like:
 * 		[
 			[
 				{"newkey":"transformed_key", "newvalue":"transformed_value", "oldkey":"original_key", "oldvalue":"original_value"},
 				{"newkey":"transformed_key_2", "newvalue":"transformed_value_2", "oldkey":"original_key_2", "oldvalue":"original_value_2"}
 			],
 			[
 				{"newkey":"transformed_key", "newvalue":"transformed_value", "oldkey":"original_key", "oldvalue":"original_value"}
 			]
 			[ ... ]
 		]
 */
func GetTransformedValues(kvList map[string]string, keyTransform func(string) string, valTransform func(string) string, transformKeys bool, transformValues bool) [][]map[string]string {
	var result [][]map[string]string //list of new (kv) maps
	for combo := range StringCombinations(Keys(kvList)) {
		var comboObj []map[string]string
		for _, k := range combo {
			values := make(map[string]string)
			values["oldkey"] = k
			values["oldvalue"] = kvList[k]
			values["newkey"] = k
			values["newvalue"] = kvList[k]
			
			if transformKeys {
				values["newkey"] = keyTransform(k)
			}
			if transformValues {
				values["newvalue"] = valTransform(kvList[k])
			}
			comboObj = append(comboObj, values)
		}
		result = append(result, comboObj)
	}
	return result
}


/**
 * return a map of true injections, with associated false injections to test.
 *
 * params:
 *   quoteType whether to use a single or double quote for injections.
 */
func JSInjections(quoteType string) map[string][]string {
	attacks := map[string][]string{}
	for _, prefix := range(data.JSPrefixes) {
		for _, suffix := range(data.JSSuffixes) {
			for _, tInjection := range(data.JSTrueStrings) {
				tInjection = prefix + tInjection + suffix
				tInjection = strings.ReplaceAll(tInjection, "'", quoteType)
				for _, finjection := range(data.JSFalseStrings) {
					finjection = prefix + finjection + suffix
					finjection = strings.ReplaceAll(finjection, "'", quoteType)
					if _, ok := attacks[tInjection]; ok {
						attacks[tInjection] = append(attacks[tInjection], finjection)
					} else {
						attacks[tInjection] = []string{finjection}
					}
				}
			}
		}
	}
	return attacks
}

/**
 * Generator function to return all combinations from a given slice.
 * A Combination is any unique (order doesn't matter) combination of
 * values.
 *
 * Example:
 * 		Combinations([1, 2, 3]) -> [1], [2], [3], [1,2], [1,3], [2,3], [1,2,3]
 */

// Combinations for a slice of strings - convert to []interface{} and pass to Combinations
func StringCombinations(data []string) <-chan []string {
	c := make(chan []string)
	iData := make([]interface{}, len(data))
	for i, v := range data {
	    iData[i] = v
	}
	go func(c chan []string) {
		defer close(c)

		for combo := range Combinations(iData...) {
			sData := make([]string, len(combo))
			for i, v := range combo {
			    sData[i] = v.(string)
			}
			c <- sData
		}
	}(c)

	return c
}

/*
 * Return all combinations of body elements in an attackObject. This is the same as string combo
 * above.
 * 
 * Parameters:
 * data: A body item list. BodyItem is defined in attack objects, and has a value and location.
 */
func BodyItemCombinations(data []BodyItem) <-chan []BodyItem {
	c := make(chan []BodyItem)
	iData := make([]interface{}, len(data))
	for i, v := range data {
	    iData[i] = v
	}
	go func(c chan []BodyItem) {
		defer close(c)

		for combo := range Combinations(iData...) {
			sData := make([]BodyItem, len(combo))
			for i, v := range combo {
			    sData[i] = v.(BodyItem)
			}
			c <- sData
		}
	}(c)

	return c
}

// Generic combinations
func Combinations(data ...interface{}) <-chan []interface{} {
	c := make(chan []interface{})
	go func(c chan []interface{}) {
		defer close(c)

		combinationsGenerator(c, data)
	}(c)

	return c
}

/**
 * Modified from MIT licensed code golang-combinations
 * just modified to use channels / as a generator rather than
 * returning the whole set at once.
 * https://github.com/mxschmitt/golang-combinations/blob/master/combinations.go
 */
func combinationsGenerator(c chan []interface{}, set []interface{}) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 0 (empty object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []interface{}

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		c <- subset
	}
}

/**
 * Generator function to return all permutations from a given slice.
 * A permutation is any unique (order does matter) combination of
 * values.
 *
 * Example:
 * 		Combinations([1, 2, 3]) ->
 * 			 [A]
 * 			 [A B]
 * 			 [A B C]
 * 			 [A C]
 * 			 [A C B]
 * 			 [B]
 * 			 [B A]
 * 			 [B A C]
 * 			 [B C]
 * 			 [B C A]
 * 			 [C]
 * 			 [C A]
 * 			 [C A B]
 * 			 [C B]
 * 			 [C B A]
 */
func Permutations(data []string) <-chan []string {
	c := make(chan []string)

	go func(c chan []string) {
		defer close(c)

		var permutations []string
		generatePermutations(c, permutations, data)
	}(c)

	return c
}

func generatePermutations(c chan []string, permutations []string, universe []string) {
	if len(universe) <= 0 {
		return
	}

	var permutation []string
	for i, str := range universe {
		permutation = append(permutation, str)
		c <- permutation
		newUniverse := append([]string(nil), universe[:i]...) //ensure we copy the slice, and don't just point to the underlying array
		newUniverse = append(newUniverse, universe[i+1:]...)

		generatePermutations(c, permutation, newUniverse)
	}
}
