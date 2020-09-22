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

/**
 * return a map of true injections, with associated false injections to test.
 *
 * params:
 *   trueInjections true to return list of always true values
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
