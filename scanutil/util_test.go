package scanutil_test

import (
	"github.com/Charlie-belmer/nosqli/scanutil"
	"reflect"
	"sort"
	"testing"
	"math"
	"flag"
	//"fmt"
)

//Unused in util package currently
var runIntegrations = flag.Bool("integrations", false, "True if we should run integrations tests dependant upon test sites running")


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
 var combinationTests = []struct {
 	name string
	input []scanutil.BodyItem
	output  [][]scanutil.BodyItem
}{
	{	"Two Element scanutil.BodyItem",
		[]scanutil.BodyItem{scanutil.BodyItem{"Some Item", 0}, scanutil.BodyItem{"Another item", 0}}, 
		[][]scanutil.BodyItem{
			{scanutil.BodyItem{"Some Item", 0}}, {scanutil.BodyItem{"Another item", 0}}, {scanutil.BodyItem{"Some Item", 0}, scanutil.BodyItem{"Another item", 0}},
		},
	},
}
func TestCombinations(t *testing.T) {
	for _, test := range combinationTests {
		t.Run(test.name, func(t *testing.T) {
			var result [][]scanutil.BodyItem
			for item := range scanutil.BodyItemCombinations(test.input) {
				result = append(result, item)
			}

			//sortEmbedded(result)
			//sortEmbedded(test.output)
			eq := reflect.DeepEqual(result, test.output)
			if !eq {
				t.Errorf("Combinations function did not return the expected combinations.\nExpected: %+v\nActual:   %+v\n", test.output, result)
			}
		})
	}
}

 var stringCombinationTests = []struct {
 	name string
	input []string
	output  [][]string
}{
	{	"Four Element slice",
		[]string{"A", "B", "C", "D"}, 
		[][]string{
			{"A"}, {"B"}, {"C"}, {"D"},
			{"A", "B"}, {"A", "C"}, {"A", "D"}, {"B", "C"}, {"C", "D"}, {"B", "D"},
			{"A", "B", "C"}, {"A", "C", "D"}, {"B", "C", "D"}, {"A", "B", "D"},
			{"A", "B", "C", "D"},
		},
	},
	{ "Single Element", []string{"A"}, [][]string{{"A"}},},
}
func TestStringCombinations(t *testing.T) {
	for _, test := range stringCombinationTests {
		t.Run(test.name, func(t *testing.T) {
			var result [][]string
			for item := range scanutil.StringCombinations(test.input) {
				result = append(result, item)
			}

			sortEmbedded(result)
			sortEmbedded(test.output)
			eq := reflect.DeepEqual(result, test.output)
			if !eq {
				t.Errorf("Combinations function did not return the expected combinations.\nExpected: %+v\nActual:   %+v\n", test.output, result)
			}
		})
	}
}
