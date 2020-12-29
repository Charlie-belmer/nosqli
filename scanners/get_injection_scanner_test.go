package scanners_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"github.com/Charlie-belmer/nosqli/scanners"
	"fmt"
)

/***********
 * Tests
***********/
var sentGETInjectionValuesTest = []struct {
	name string
	paramname  string
	paramvalue string
	expectedInjection string
}{
	{"Baseline request", "param", "value", "param[$ne]=value"},
	{"Added some value", "param", "value", "param[$gt]=a"},
}
func TestGetInjectionValues(t *testing.T) {
	for _, test := range sentGETInjectionValuesTest {
		t.Run(test.name, func(t *testing.T) {
			seen := false
	    	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	    		w.Header().Set("Content-Type", "application/json")
		    	u, _ := url.QueryUnescape(r.URL.RawQuery)
		    	fmt.Printf("Saw this query: %+v\n", u)
		    	if u == test.expectedInjection {
		    		seen = true
		    	}
		        
		    }))
		    defer ts.Close()

		    url := ts.URL + "?" + test.paramname + "=" + test.paramvalue
			att := setup(t, url, "")
			scanners.GetInjectionTest(att)

			if !seen{
				t.Errorf("Missing injection string: %+v\n", test.expectedInjection)
			}
			
		})
	}
}

/***********
 * Tests
***********/
var sentMultipleGETInjectionValuesTest = []struct {
	name string
	param1name  string
	param1value string
	param2name  string
	param2value string
	expectedInjection string
}{
	{"Baseline request", "param1", "value1", "param2", "value2", "param1[$ne]=&param2[$gt]=value2"},
	{"Baseline request", "param1", "value1", "param2", "value2", "param1[$ne]=a&param2[$gt]=value2"},
	{"Baseline request", "param1", "value1", "param2", "value2", "param1[$ne]=value1&param2[$ne]="},
	{"Baseline request", "param1", "value1", "param2", "value2", "param1[$ne]=value1&param2[$ne]=a"},
	{"Added some value", "param1", "value1", "param2", "value2", "param1[$gt]=&param2[$ne]="},
}
func TestGetInjectionMultipleValues(t *testing.T) {
	for _, test := range sentMultipleGETInjectionValuesTest {
		t.Run(test.name, func(t *testing.T) {
			seen := false
	    	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	    		w.Header().Set("Content-Type", "application/json")
		    	u, _ := url.QueryUnescape(r.URL.RawQuery)
		    	fmt.Printf("Saw this query: %+v\n", u)
		    	if u == test.expectedInjection {
		    		seen = true
		    	}
		        
		    }))
		    defer ts.Close()

		    url := ts.URL + "?" + test.param1name + "=" + test.param1value + "&" + test.param2name + "=" + test.param2value
			att := setup(t, url, "")
			scanners.GetInjectionTest(att)

			if !seen{
				t.Errorf("Missing injection string: %+v\n", test.expectedInjection)
			}
			
		})
	}
}


/***********
 * Integration Tests
 * 	Depends on a local vulnerable node app for testing: https://github.com/Charlie-belmer/vulnerable-node-app
***********/

var GETInjectionIntegrationTest = []struct {
	name string
	url  string
	injectionsFound int
	injectableParams []string
}{
	{"Correct user param, correct type param", "http://localhost:8081/user_lookup.php?type=user&username=joe", 2, []string{"type", "username"}},
	{"Correct user param, Incorrect type param, ", "http://localhost:8081/user_lookup.php?type=a&username=joe", 2, []string{"type", "username"}},
	{"Correct user param, Empty type param", "http://localhost:8081/user_lookup.php?type=&username=joe", 2, []string{"type", "username"}},
	{"Correct user param, admin type param", "http://localhost:8081/user_lookup.php?type=admin&username=joe", 2, []string{"type", "username"}},
	{"Incorrect user param, correct type param", "http://localhost:8081/user_lookup.php?type=user&username=a", 2, []string{"type", "username"}},
	{"Incorrect user param, Incorrect type param", "http://localhost:8081/user_lookup.php?type=a&username=a", 2, []string{"type", "username"}},
	{"Incorrect user param, empty type param", "http://localhost:8081/user_lookup.php?type=&username=a", 2, []string{"type", "username"}},
	{"Incorrect user param, admin type param", "http://localhost:8081/user_lookup.php?type=admin&username=a", 2, []string{"type", "username"}},
	{"Empty user param, correct type param", "http://localhost:8081/user_lookup.php?type=user&username=", 2, []string{"type", "username"}},
	{"Empty user param, incorrect type param", "http://localhost:8081/user_lookup.php?type=a&username=", 2, []string{"type", "username"}},
	{"Empty user param, empty type param", "http://localhost:8081/user_lookup.php?type=&username=", 2, []string{"type", "username"}},
	{"Empty user param, admin type param", "http://localhost:8081/user_lookup.php?type=admin&username=", 2, []string{"type", "username"}},
}
func TestGETInjectionIntegration(t *testing.T) {
	if *runIntegrations {
		for _, test := range GETInjectionIntegrationTest {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.GetInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("%+v:\nMismatch in findings length with url %+v\nGot: %+v findings. \nExpected: %+v\nGot: %#v\n\n", test.name, test.url, len(injectables), test.injectionsFound, injectables)
				}
				for _, param := range test.injectableParams {
					found_param := false
					for _, i := range injectables {
						if i.InjectableParam == param {
							found_param = true
						}
					}
					if ! found_param {
						t.Errorf("%+v:\n Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", test.name, param, test.url, injectables)
					}
				}
			})
		}
	}
}