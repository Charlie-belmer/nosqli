package scanners_test

import (
	"github.com/Charlie-belmer/nosqli/scanners"
	"testing"
	"net/http"
	"net/http/httptest"
	"net/url"
	//"fmt"
)


var sentErrorGETValuesTest = []struct {
	name string
	paramname  string
	paramvalue string
	expectedInjection string
}{
	{"Baseline request", "param", "value", "param='"},
}
func TestErrorGETInjectionValues(t *testing.T) {
	for _, test := range sentErrorGETValuesTest {
		t.Run(test.name, func(t *testing.T) {
			seen := false
	    	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	    		w.Header().Set("Content-Type", "application/json")
		    	u, _ := url.QueryUnescape(r.URL.RawQuery)
		    	if u == test.expectedInjection {
		    		seen = true
		    	}
		        
		    }))
		    defer ts.Close()

		    url := ts.URL + "?" + test.paramname + "=" + test.paramvalue
			att := setup(t, url, "")
			scanners.ErrorBasedInjectionTest(att)

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

/**
 * Test that GET injections work with real vulnerable services. Requires that the expected test servers are running on localhost:4000
**/
var IntegrationErrorGETValues = []struct {
	name string
	url  string
	injectionsFound int
}{
	{"Correct param", "http://localhost:4000/user/lookup?username=guest", 1},
	{"Incorrect param", "http://localhost:4000/user/lookup?username=guester", 1},
	{"Empty param", "http://localhost:4000/user/lookup?username=", 1},
}
func TestIntegrationErrorGET(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationErrorGETValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.ErrorBasedInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length\nGot: %+v findings. Expected: %+v\nGot: %#v\n", len(injectables), test.injectionsFound, injectables)
				}
			})
		}
	}
}


var IntegrationErrorRegexGETValues = []struct {
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
func TestIntegrationErrorRegexGET(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationErrorRegexGETValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.ErrorBasedInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length with url %+v\nGot: %+v findings. \nExpected: %+v\nGot: %#v\n\n", test.url, len(injectables), test.injectionsFound, injectables)
				}
				for _, param := range test.injectableParams {
					found_param := false
					for _, i := range injectables {
						if i.InjectableParam == param {
							found_param = true
						}
					}
					if ! found_param {
						t.Errorf("Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", param, test.url, injectables)
					}
				}
			})
		}
	}
}

/**
 * Test ability to detect errors when data POSTED paramters sent via JSON.
 */ 
var IntegrationErrorRegexPOSTValues = []struct {
	name string
	url  string
	body string
	injectionsFound int
	injectableParams []string
}{
	{"correct user param, incorrect password param", "http://localhost:4000/user/login", `{"username":"guest","password":"pass"}`, 2, []string{"guest", "pass"}},
	{"incorrect user param, incorrect password param", "http://localhost:4000/user/login", `{"username":"something","password":"pass"}`, 2, []string{"something", "pass"}},
	{"password == 'password'", "http://localhost:4000/user/login", `{"username":"something","password":"password"}`, 2, []string{"something", "password"}},
	{"username == 'username'", "http://localhost:4000/user/login", `{"username":"username","password":"pass"}`, 2, []string{"username", "pass"}},
}
func TestIntegrationErrorRegexPOST(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationErrorRegexPOSTValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, test.body)
				injectables := scanners.ErrorBasedInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length with url %+v\nGot: %+v findings. \nExpected: %+v\nGot: %#v\n\n", test.url, len(injectables), test.injectionsFound, injectables)
				}
				for _, param := range test.injectableParams {
					found_param := false
					for _, i := range injectables {
						if i.InjectableParam == param {
							found_param = true
						}
					}
					if ! found_param {
						t.Errorf("Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", param, test.url, injectables)
					}
				}
			})
		}
	}
}