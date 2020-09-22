package scanners_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"github.com/Charlie-belmer/nosqli/scanners"
)

/***********
 * Tests
***********/
var timingGetTests = []struct {
	name                    string
	sleepParam              string
	defaultparam            string
	expectedNumFindings     int
	expectedInjectionValues []string
}{
	{"notices minimum delay", "param=data';sleep(500);", "param=data", 1, []string{"true: data' || 'a'=='a' || 'a'=='a, false: data' && 'a'!='a' && 'a'!='a"}},
}

func TestTimingInjectionGetRequests(t *testing.T) {
	for _, test := range timingGetTests {
		t.Run(test.name, func(t *testing.T) {
			didInject := false
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				u, _ := url.QueryUnescape(r.URL.RawQuery)
				switch u {
				case test.sleepParam:
					didInject = true
					fmt.Fprintln(w, "")
				case test.defaultparam:
					fmt.Fprintln(w, "")
				default:
					//Return an error by default, since timing injection ignores error responses. This ensures that we only get the results we want.
					fmt.Fprintln(w, "SyntaxError: unterminated string literal")
				}
				// uncomment to view all requests in output
				//fmt.Printf("%+v\n", u)

			}))
			defer ts.Close()

			url := ts.URL + "?" + test.defaultparam
			att := setup(t, url, "")
			scanners.TimingInjectionTest(att)

			if !didInject {
				t.Errorf("Expected to see: %+v, but no injection of that kind found.\n", test.sleepParam)
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
var IntegrationTimingGETValues = []struct {
	name            string
	url             string
	injectionsFound int
}{
	{"correct param", "http://localhost:4000/user/lookup?username=guest", 4},
	{"Incorrect param", "http://localhost:4000/user/lookup?username=guester", 4},
	{"Empty param", "http://localhost:4000/user/lookup?username=", 2},
}

func TestIntegrationTimingGET(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationTimingGETValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.TimingInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length\nGot: %+v findings. Expected: %+v\nGot: %#v\n", len(injectables), test.injectionsFound, injectables)
				}
			})
		}
	}
}

/**
 * Post injections
**/
var IntegrationTimingPOSTValues = []struct {
	name             string
	url              string
	body             string
	injectionsFound  int
}{
	{"Param is blank", "http://localhost:4000/user/lookup", `{"username":""}`, 2},
	{"incorrect user param", "http://localhost:4000/user/lookup", `{"username":"foo"}`, 4},
	{"correct user param", "http://localhost:4000/user/lookup", `{"username":"guest"}`, 4},
}

func TestIntegrationTimingPOST(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationTimingPOSTValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, test.body)
				injectables := scanners.TimingInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length\nGot: %+v findings. Expected: %+v\nGot: %#v\n", len(injectables), test.injectionsFound, injectables)
				}
			})
		}
	}
}

/**
 * Object injections
**/
var IntegrationTimingObjectPOSTValues = []struct {
	name             string
	url              string
	body             string
	injectionsFound  int
}{
	{"Param is blank", "http://localhost:4000/user/lookup2", `{"username":""}`, 1},
	{"incorrect user param", "http://localhost:4000/user/lookup2", `{"username":"foo"}`, 1},
	{"correct user param", "http://localhost:4000/user/lookup2", `{"username":"guest"}`, 1},
}

func TestIntegrationTimingObjectPOST(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationTimingObjectPOSTValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, test.body)
				injectables := scanners.TimingInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length\nGot: %+v findings. Expected: %+v\nGot: %#v\n", len(injectables), test.injectionsFound, injectables)
				}
			})
		}
	}
}