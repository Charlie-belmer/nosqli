package tests

import (
	"testing"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"reflect"
	"fmt"
	"sort"
	"net/url"
)

func TestSetQueryParam(t *testing.T) {
	testurl := "http://www.test.com/page?key1=value1&key2=value2&key3=value3"
	replaceurl1 := "http://www.test.com/page?key1=replaced&key2=value2&key3=value3"
	replaceurl2 := "http://www.test.com/page?key1=value1&key2=replaced&key3=value3"
	replaceurl3 := "http://www.test.com/page?key1=value1&key2=value2&key3=replaced"
	var scanOptions = scanutil.ScanOptions{Target: testurl}
	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		t.Errorf("Did not create attack object successfully.\n%s", err)
	}
	att.SetQueryParam("key1", "replaced")
	if att.Request.URL.String() != replaceurl1 {
		t.Errorf("Did not update URL GET parameter correctly\nExpected: %s\nActual:   %s\n", replaceurl1, att.Request.URL.String())
	}
	att, err = scanutil.NewAttackObject(scanOptions)
	if err != nil {
		t.Errorf("Did not create attack object successfully.\n%s", err)
	}
	att.SetQueryParam("key2", "replaced")
	if att.Request.URL.String() != replaceurl2 {
		t.Errorf("Did not update URL GET parameter correctly\nExpected: %s\nActual:   %s\n", replaceurl2, att.Request.URL.String())
	}
	att, err = scanutil.NewAttackObject(scanOptions)
	if err != nil {
		t.Errorf("Did not create attack object successfully.\n%s", err)
	}
	att.SetQueryParam("key3", "replaced")
	if att.Request.URL.String() != replaceurl3 {
		t.Errorf("Did not update URL GET parameter correctly\nExpected: %s\nActual:   %s\n", replaceurl3, att.Request.URL.String())
	}

}


/** 
 *	Make sure that when creating an object with a body that uses form values, 
 * that the form key and value data are correclty extracted.
 */
func TestSetBodyQueryValues(t *testing.T) {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		t.Errorf("Did not create attack object successfully.\n%s", err)
	}
	att.SetBody("key1=value1&key2=value2&key3=value3")

	expect := []string{"key1", "value1", "key2", "value2", "key3", "value3"}
	//Values may not be in the same order, so let's sort both.
	sort.SliceStable(expect, func(i, j int) bool { return expect[i] < expect[j] })
	values := att.BodyValues
	sort.SliceStable(values, func(i, j int) bool { return values[i] < values[j] })
	eq := reflect.DeepEqual(expect, values)
	if !eq {
		t.Errorf("Body values not extracted correctly for form data\nExpected: %s\nActual:   %s\n", expect, values)
	}
}

/** 
 *	Make sure that when creating an object with a body that uses form values, 
 * that the form key and value data are correclty extracted.
 */
func TestSetBodyJSON(t *testing.T) {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		t.Errorf("Did not create attack object successfully.\n%s", err)
	}
	att.SetBody(`{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else"}`)

	expect := []string{`key1`, `{"subkey": "value","subkey2": ["one", "two", "three"]}`, `subkey`, `value`, `subkey2`, `["one", "two", "three"]`, `one`, `two`, `three`, `key2`, `something else`}
	eq := reflect.DeepEqual(expect, att.BodyValues)
	if !eq {
		t.Errorf("Body values not extracted correctly for form data.\nExpected: %s\nActual:   %s\n", expect, att.BodyValues)
	}
}

/** 
 *	Ensure that injecting attack strings into JSON bodies works as expected.
 */
func TestReplaceBodyJSON(t *testing.T) {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Did not create attack object successfully")
	}
	att.SetBody(`{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	expect := `{"key1": {"substitute": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject("subkey", `"substitute"`, true)
	eq := reflect.DeepEqual(expect, att.Body)

	if !eq {
		t.Errorf("Simple string not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject(`["one", "two", "three"]`, `"Attack|String"`, false)
	expect = `{"key1": {"subkey": "value","subkey2": "Attack|String"}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Array not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject("2", `"Attack|String"`, false)
	expect = `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": "Attack|String", "key4": [12,"Attack|String",3,"Attack|String"]}`
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject(`{"subkey": "value","subkey2": ["one", "two", "three"]}`, `"Attack|String"`, false)
	expect = `{"key1": "Attack|String", "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Object not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

/** 
 *	Ensure that injecting attack strings into QueryString bodies works as expected.
 */
func TestReplaceBodyQueryString(t *testing.T) {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}
	params := url.Values{}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Did not create attack object successfully")
	}

	att.SetBody(`key1=value1&someforminfo=some nice form data&another key=1`)

	// Build query string with expected values, and encode it properly.
	params.Add("key1", "value1")
	params.Add("someforminfo", "some nice form data")
	params.Add("another key", "1")
	expect := params.Encode()
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Body not initially set correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.ReplaceBodyObject("key1", "Attack|String", true)
	params.Del("key1")
	params.Add("Attack|String", "value1")
	expect = params.Encode()
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Object not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	params.Add("key1", "value1")
	params.Del("Attack|String")
	params.Set("another key", "Attack|String")
	att.RestoreBody()
	att.ReplaceBodyObject("1", "Attack|String", false)
	expect = params.Encode()
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer value not replaced correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	params.Set("another key", "1")
	params.Set("someforminfo", "Attack|String")
	att.RestoreBody()
	att.ReplaceBodyObject("some+nice+form+data", "Attack|String", false)
	expect = params.Encode()
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer value not replaced correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

/** 
 *	Ensure that injecting attack strings into QueryString bodies works as expected.
 */
func TestCombinations(t *testing.T) {
	data := []string{"A", "B", "C", "D"}
	//expect := []string{["A"], ["B"], ["C"], ["A", "B"], ["A", "C"], ["B", "C"], ["A", "B", "C"]}
	for item := range(scanutil.Combinations(data)) {
		fmt.Printf("Function generated %s\n",item)
	}
}