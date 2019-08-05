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

import ()

// Generic utility functions

/**
 * Generator function to return all combinations from a given slice.
 * A Combination is any unique (order doesn't matter) combination of
 * values.
 *
 * Example:
 * 		Combinations([1, 2, 3]) -> [1], [2], [3], [1,2], [1,3], [2,3], [1,2,3]
 */
func Combinations(data []string) <-chan []string {
	c := make(chan []string)

	go func(c chan []string) {
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
func combinationsGenerator(c chan []string, set []string) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []string

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		//subsets = append(subsets, subset)
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
