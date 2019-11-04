package scanutil_test

import (
	"github.com/Charlie-belmer/nosqli/scanutil"
	"reflect"
	"sort"
	"testing"
	"math"
)


/**
 * sorting function that compares two string slices
 */
func cmpSlice(s1, s2 []string) bool {
	for i := 0; i < int(math.Min(float64(len(s1)), float64(len(s2)))); i++ {
		if s1[i] < s2[i] {
			return true
		} else if s1[i] < s2[i] {
			return false
		}
		
	}
	if len(s1) < len(s2) {
		return true
	}
	return false
}

/**
 * Deeply sort a list of list of strings
 */
func sortEmbedded(s [][]string) {
	// sort sub-slices
	for _, s2 := range s {
		sort.SliceStable(s2, func(i, j int) bool { return s2[i] < s2[j] })
	}

	sort.SliceStable(s, func(i, j int) bool { return cmpSlice(s[i],s[j]) })
}

/**
 *	Determine all combinations are successfully generated.
 */
func TestCombinations(t *testing.T) {
	data := []string{"A", "B", "C", "D"}
	expect := [][]string{
		{"A"}, {"B"}, {"C"}, {"D"},
		{"A", "B"}, {"A", "C"}, {"A", "D"}, {"B", "C"}, {"C", "D"}, {"B", "D"},
		{"A", "B", "C"}, {"A", "C", "D"}, {"B", "C", "D"}, {"A", "B", "D"},
		{"A", "B", "C", "D"},
	}
	var result [][]string
	for item := range scanutil.Combinations(data) {
		result = append(result, item)
	}

	sortEmbedded(result)
	sortEmbedded(expect)
	eq := reflect.DeepEqual(result, expect)
	if !eq {
		t.Errorf("Combinations function did not return the expected combinations.\nExpected: %s\nActual:   %s\n", expect, result)
	}
	
}
