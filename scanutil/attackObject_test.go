package scanutil_test

import (
	"fmt"
	"github.com/Charlie-belmer/nosqli/scanutil"
	"net/url"
	"reflect"
	"sort"
	"testing"
)

/***********
 * Setup objects and mocks
***********/
func setup(t *testing.T, body string) scanutil.AttackObject {
	testurl := "http://www.test.com/"
	var scanOptions = scanutil.ScanOptions{Target: testurl}

	att, err := scanutil.NewAttackObject(scanOptions)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Did not create attack object successfully")
	}
	att.SetBody(body)
	return att
}

/***********
 * Tests
***********/

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
	att := setup(t, "key1=value1&key2=value2&key3=value3")

	expect := []scanutil.BodyItem{{"key1",0}, {"value1",0}, {"key2",0}, {"value2",0}, {"key3",0}, {"value3",0}}
	//Values may not be in the same order, so let's sort both.
	sort.SliceStable(expect, func(i, j int) bool { return expect[i].Value < expect[j].Value })
	values := att.BodyValues
	sort.SliceStable(values, func(i, j int) bool { return values[i].Value < values[j].Value })
	eq := reflect.DeepEqual(expect, values)
	if !eq {
		t.Errorf("Body values not extracted correctly for form data\nExpected: %v\nActual:   %v\n", expect, values)
	}
}

/**
 *	Make sure that when creating an object with a body that uses JSON values,
 * that the form key and value data are correclty extracted.
 */
func TestSetBodyJSON(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else"}`)
	
	expect := []scanutil.BodyItem{
		{`key1`,0}, 
		{`{"subkey": "value","subkey2": ["one", "two", "three"]}`,0},
		{`subkey`,0}, 
		{`value`,0}, 
		{`subkey2`,0}, 
		{`["one", "two", "three"]`,0}, 
		{`one`,0}, 
		{`two`,0}, 
		{`three`,0}, 
		{`key2`,0}, 
		{`something else`,0},
	}
	eq := reflect.DeepEqual(expect, att.BodyValues)
	if !eq {
		t.Errorf("Body values not extracted correctly for form data.\nExpected: %v\nActual:   %v\n", expect, att.BodyValues)
	}
}

/**
 *	Ensure that injecting attack strings into JSON bodies works as expected.
 * TODO: Add tests around single value / index replacements
 */
func TestReplaceBodyJSONSubkey(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	expect := `{"key1": {"substitute": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject("subkey", `"substitute"`, true, -1)
	eq := reflect.DeepEqual(expect, att.Body)

	if !eq {
		t.Errorf("Simple string not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

func TestReplaceBodyJSONArray(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)
	att.ReplaceBodyObject(`["one", "two", "three"]`, `"Attack|String"`, false, -1)
	expect := `{"key1": {"subkey": "value","subkey2": "Attack|String"}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Array not substituted correctly.\nPattern: [\"one\", \"two\", \"three\"] \nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

func TestReplaceBodyJSONInteger(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)
	att.ReplaceBodyObject("2", `"Attack|String"`, false, -1)
	expect := `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": "Attack|String", "key4": [12,"Attack|String",3,"Attack|String"]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

func TestReplaceBodyJSONObject(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)
	att.ReplaceBodyObject(`{"subkey": "value","subkey2": ["one", "two", "three"]}`, `"Attack|String"`, false, -1)
	expect := `{"key1": "Attack|String", "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Object not substituted correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

// Ensure we can replace only a single string instance at a time
func TestReplaceBodyJSONSinglePatternInstanceString(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "one", "one"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	expect := `{"key1": {"subkey": "value","subkey2": ["Attack|String", "one", "one"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject(`one`, `"Attack|String"`, true, 0)
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Item not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.SetBody(`{"key1": {"subkey": "value","subkey2": ["one", "one", "one"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)
	expect = `{"key1": {"subkey": "value","subkey2": ["one", "Attack|String", "one"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject(`one`, `"Attack|String"`, true, 1)
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Item not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.SetBody(`{"key1": {"subkey": "value","subkey2": ["one", "one", "one"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)
	expect = `{"key1": {"subkey": "value","subkey2": ["one", "one", "Attack|String"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject(`one`, `"Attack|String"`, true, 2)
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Item not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

// Ensure we can replace only a single array instance at a time
func TestReplaceBodyJSONSinglePatternInstanceArray(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	att.ReplaceBodyObject(`["one", "two", "three"]`, `"Attack|String"`, false, 0)
	expect := `{"key1": {"subkey": "value","subkey2": "Attack|String"}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Array not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

// Ensure we can replace only a single array instance at a time
func TestReplaceBodyJSONSinglePatternInstanceInteger(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	att.ReplaceBodyObject("2", `"Attack|String"`, false, 0)
	expect := `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": "Attack|String", "key4": [12,2,3,2]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

// Ensure we can replace only a single object instance at a time
func TestReplaceBodyJSONSinglePatternInstanceObject(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	att.ReplaceBodyObject(`{"subkey": "value","subkey2": ["one", "two", "three"]}`, `"Attack|String"`, false, 0)
	expect := `{"key1": "Attack|String", "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Object not substituted correctly with index.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

// Ensure we handle cases where index > number of values.
func TestReplaceBodyJSONLargeIndex(t *testing.T) {
	att := setup(t, `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`)

	expect := `{"key1": {"subkey": "value","subkey2": ["one", "two", "three"]}, "key2": "something else", "key3": 2, "key4": [12,2,3,2]}`
	att.ReplaceBodyObject("subkey", `"substitute"`, true, 5)
	eq := reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Simple string not substituted correctly with index > matches.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject(`["one", "two", "three"]`, `"Attack|String"`, false, 5)
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Array not substituted correctly with index > matches.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject("2", `"Attack|String"`, false, 5)
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer not substituted correctly with index > matches.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	att.RestoreBody()
	att.ReplaceBodyObject(`{"subkey": "value","subkey2": ["one", "two", "three"]}`, `"Attack|String"`, false, 5)
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Object not substituted correctly with index > matches.\nExpected: %s\nActual:   %s\n", expect, att.Body)
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

	att.ReplaceBodyObject("key1", "Attack|String", true, -1)
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
	att.ReplaceBodyObject("1", "Attack|String", false, -1)
	expect = params.Encode()
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer value not replaced correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}

	params.Set("another key", "1")
	params.Set("someforminfo", "Attack|String")
	att.RestoreBody()
	att.ReplaceBodyObject("some+nice+form+data", "Attack|String", false, -1)
	expect = params.Encode()
	eq = reflect.DeepEqual(expect, att.Body)
	if !eq {
		t.Errorf("Integer value not replaced correctly.\nExpected: %s\nActual:   %s\n", expect, att.Body)
	}
}

func TestCopy(t *testing.T) {
	att := setup(t, `{"key": "some body data"}`)
	att2 := att.Copy()
	att2.ReplaceBodyObject("key", "something new", false, -1)
	if att.Hash() == att2.Hash() {
		t.Errorf("Copies are synchronized. Expected to be different\n Object1: %+v\nObject2: %+v", att, att2)
	}
	testurl := "http://www.test.com/page?key1=value1&key2=value2&key3=value3"
	var scanOptions = scanutil.ScanOptions{Target: testurl}
	att, _ = scanutil.NewAttackObject(scanOptions)
	att2 = att.Copy()
	att2.SetQueryParam("key1", "replaced")
	if att.Hash() == att2.Hash() {
		t.Errorf("Requests are synchronized. Expected to be different\n Object1: %+v\nObject2: %+v\nRequest1: %+v\nRequest2: %+v\n", att, att2, att.Request, att2.Request)
	}
}