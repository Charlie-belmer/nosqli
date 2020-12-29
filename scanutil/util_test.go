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

func sortDeepMap(m [][]map[string]string) {
	for _, sl := range m {
		sort.SliceStable(sl, func(i,j int) bool { return sl[i]["newkey"] < sl[j]["newkey"] })
	}

	sort.SliceStable(m, func(i,j int) bool { return m[i][0]["newkey"] < m[j][0]["newkey"] })
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


var mapKeysTests = []struct {
 	name 	string
	input 	map[string]string
	output  []string
}{
	{	"simple key,value pairs",
		map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4"}, 
		[]string{"k1", "k2", "k3", "k4"},
	},
	{ "Single Element", map[string]string{"k1": "v1"}, []string{"k1"},},
}
func TestMapKeyExtraction(t *testing.T) {
	for _, test := range mapKeysTests {
		t.Run(test.name, func(t *testing.T) {
			result := scanutil.Keys(test.input)
			sort.SliceStable(result, func(i, j int) bool { return result[i] < result[j] })
			sort.SliceStable(test.output, func(i, j int) bool { return test.output[i] < test.output[j] })
			eq := reflect.DeepEqual(result, test.output)
			if !eq {
				t.Errorf("Keys incorrectly extracted.\nExpected: %+v\nActual:   %+v\n", test.output, result)
			}
		})
	}
}

var mapValuesTests = []struct {
 	name 	string
	input 	map[string]string
	output  []string
}{
	{	"simple key,value pairs",
		map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4"}, 
		[]string{"v1", "v2", "v3", "v4"},
	},
	{ "Single Element", map[string]string{"k1": "v1"}, []string{"v1"},},
}
func TestMapValueExtraction(t *testing.T) {
	for _, test := range mapValuesTests {
		t.Run(test.name, func(t *testing.T) {
			result := scanutil.Values(test.input)
			sort.SliceStable(result, func(i, j int) bool { return result[i] < result[j] })
			sort.SliceStable(test.output, func(i, j int) bool { return test.output[i] < test.output[j] })
			eq := reflect.DeepEqual(result, test.output)
			if !eq {
				t.Errorf("Values incorrectly extracted.\nExpected: %+v\nActual:   %+v\n", test.output, result)
			}
		})
	}
}

var getTransformedValuesTests = []struct {
 	name 	string
 	kvList map[string]string
 	keyTransform func(string) string
 	valTransform func(string) string
 	shouldTransformKey bool
 	shouldTransformValue bool
	output  [][]map[string]string
}{
	{	"Tansform single value",
		map[string]string{"k1": "v1"}, 
		func(s string) string { return s + "akey" },
		func(s string) string { return s + "avalue" },
		true,
		true,
		[][]map[string]string { 
			[]map[string]string{
				map[string]string {"newkey":"k1akey", "newvalue":"v1avalue", "oldkey":"k1", "oldvalue":"v1"},
			},
		},
	},
	{	"Tansform single value, but not the key",
		map[string]string{"k1": "v1"}, 
		func(s string) string { return s + "akey" },
		func(s string) string { return s + "avalue" },
		false,
		true,
		[][]map[string]string {
			[]map[string]string{
				map[string]string {"newkey":"k1", "newvalue":"v1avalue", "oldkey":"k1", "oldvalue":"v1"},
			},
		},
	},
	{	"Tansform single value, but not the value",
		map[string]string{"k1": "v1"}, 
		func(s string) string { return s + "akey" },
		func(s string) string { return s + "avalue" },
		true,
		false,
		[][]map[string]string {
			[]map[string]string{
				map[string]string {"newkey":"k1akey", "newvalue":"v1", "oldkey":"k1", "oldvalue":"v1"},
			},
		},
	},
	{	"Tansform two values",
		map[string]string{"k1": "v1", "k2": "v2"}, 
		func(s string) string { return s + "akey" },
		func(s string) string { return s + "avalue" },
		true,
		true,
		[][]map[string]string {
			[]map[string]string{
				map[string]string {"newkey":"k1akey", "newvalue":"v1avalue", "oldkey":"k1", "oldvalue":"v1"},
			},
			[]map[string]string{
				map[string]string {"newkey":"k2akey", "newvalue":"v2avalue", "oldkey":"k2", "oldvalue":"v2"},
			},
			[]map[string]string{
				map[string]string {"newkey":"k1akey", "newvalue":"v1avalue", "oldkey":"k1", "oldvalue":"v1"},
				map[string]string {"newkey":"k2akey", "newvalue":"v2avalue", "oldkey":"k2", "oldvalue":"v2"},
			},
		},
	},
}
func TestGetTransformedValues(t *testing.T) {
	for _, test := range getTransformedValuesTests {
		t.Run(test.name, func(t *testing.T) {
			result := scanutil.GetTransformedValues(test.kvList, test.keyTransform, test.valTransform, test.shouldTransformKey, test.shouldTransformValue)
			sortDeepMap(result)
			sortDeepMap(test.output)
			eq := reflect.DeepEqual(result, test.output)
			if !eq {
				t.Errorf("Values transformed incorrectly.\nExpected: %+v\nActual:   %+v\n", test.output, result)
			}
		})
	}
}
