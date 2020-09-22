package scanners_test

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Charlie-belmer/nosqli/scanners"
	"github.com/Charlie-belmer/nosqli/scanutil"
)

var runIntegrations = flag.Bool("integrations", false, "True if we should run integrations tests dependant upon test sites running")

/***********
 * Setup objects and mocks
***********/

func setup(t *testing.T, url, body string) scanutil.AttackObject {
	var scanOptions = scanutil.ScanOptions{Target: url}

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
var booleanGetTests = []struct {
	name                    string
	trueparam               string
	falseparam              string
	defaultparam            string
	trueresponse            string
	falseresponse           string
	defaultresponse         string
	expectedNumFindings     int
	expectedInjectionValues []string
}{
	{"False and default differ", "param=data' || 'a'=='a' || 'a'=='a", "param=data' && 'a'!='a' && 'a'!='a", "param=data", "true", "false", "true", 1, []string{"true: data' || 'a'=='a' || 'a'=='a, false: data' && 'a'!='a' && 'a'!='a"}},
	{"True and default differ", "param=data' || 'a'=='a' || 'a'=='a", "param=data' && 'a'!='a' && 'a'!='a", "param=data", "true", "false", "false", 1, []string{"true: data' || 'a'=='a' || 'a'=='a, false: data' && 'a'!='a' && 'a'!='a"}},
	{"List Response no param", "param=' || 'a'=='a' || 'a'=='a", "param=' && 'a'!='a' && 'a'!='a", "param=", "row1<br />row2", "no results found", "no results found", 1, []string{"true: ' || 'a'=='a' || 'a'=='a, false: ' && 'a'!='a' && 'a'!='a"}},
	{"List Response correct param", "param=good' && 'a'=='a' && 'a'=='a", "param=good' && 'a'!='a' && 'a'!='a", "param=good", "row1", "no results found", "row1", 1, []string{"true: good' && 'a'=='a' && 'a'=='a, false: good' && 'a'!='a' && 'a'!='a"}},
	{"List Response bad param", "param=bad' || 'a'=='a' || 'a'=='a", "param=bad' && 'a'!='a' && 'a'!='a", "param=bad", "row1<br />row2", "no results found", "no results found", 1, []string{"true: bad' || 'a'=='a' || 'a'=='a, false: bad' && 'a'!='a' && 'a'!='a"}},
}

func TestBooleanInjectionGetRequests(t *testing.T) {
	for _, test := range booleanGetTests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				u, _ := url.QueryUnescape(r.URL.RawQuery)
				switch u {
				case test.trueparam:
					fmt.Fprintln(w, test.trueresponse)
				case test.falseparam:
					fmt.Fprintln(w, test.falseresponse)
				case test.defaultparam:
					fmt.Fprintln(w, test.defaultresponse)
				default:
					//Return an error by default, since boolean injection ignores error responses. This ensures that we only get the results we want.
					fmt.Fprintln(w, "SyntaxError: unterminated string literal")
				}
				// uncomment to view all requests in output
				//fmt.Printf("%+v\n", u)

			}))
			defer ts.Close()

			url := ts.URL + "?" + test.defaultparam
			att := setup(t, url, "")
			injectables := scanners.BlindBooleanInjectionTest(att)

			if len(injectables) != test.expectedNumFindings {
				t.Errorf("Mismatch in findings length\nObject: %+v\n\nGot: %+v findings. Expected: %+v\nGot: %#v\n Expected: %+v\n", att, len(injectables), test.expectedNumFindings, injectables, test.expectedInjectionValues)
			}
			for i, injectable := range injectables {
				if i >= len(test.expectedInjectionValues) {
					//already handled above
					continue
				} else if injectable.InjectedValue != test.expectedInjectionValues[i] {
					t.Errorf("Mismatch in injected values:\nGot: %+v\nExpected: %+v\n", injectable.InjectedValue, test.expectedInjectionValues[i])

				}
			}

		})
	}
}

/**
 * Test that certain injection strings are being sent in GET requests - that the proper combinations of data, prefix, and suffix are being generated
**/
var sentGETValuesTest = []struct {
	name              string
	paramname         string
	paramvalue        string
	expectedInjection string
}{
	{"Baseline request", "param", "value", "param=value"},
	{"True JS with param", "param", "value", "param=value' || 'a'=='a' || 'a'=='a"},
	{"False JS with param", "param", "value", "param=value' && 'a'!='a' && 'a'!='a"},
}

func TestBooleanGETInjectionValues(t *testing.T) {
	for _, test := range sentGETValuesTest {
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
			scanners.BlindBooleanInjectionTest(att)

			if !seen {
				t.Errorf("Missing injection string: %+v\n", test.expectedInjection)
			}

		})
	}
}

// Ensure we are being minimal in requests - don't send duplicate injection strings
func TestNoDuplicateGETRequests(t *testing.T) {
	seen := map[string]int{}
	duplicate_count := 0
	requests := 0
	params := "param=value&param2=value2"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		u, _ := url.QueryUnescape(r.URL.RawQuery)
		if _, ok := seen[u]; ok {
			if u == params {
				return //ignore default / baseline requests
			}
			seen[u]++
			t.Errorf("Duplicate - Seen injection string %+v times: %+v\n", seen[u], u)
			duplicate_count++
		} else {
			seen[u] = 1
		}
		requests++

	}))
	defer ts.Close()

	url := ts.URL + "?" + params
	att := setup(t, url, "")
	scanners.BlindBooleanInjectionTest(att)
	if duplicate_count > 0 {
		t.Errorf("Duplicate injections sent: %+v/%+v\n", duplicate_count, requests)
	}
}

/***********
 * Integration Tests
 * 	Depends on a local vulnerable node app for testing: https://github.com/Charlie-belmer/vulnerable-node-app
***********/

/**
 *	Test that the integration services are running
 */
func TestIntegrationServicesUP(t *testing.T) {
	if *runIntegrations {
		timeout := time.Duration(1 * time.Second)
		sites := []string{"localhost:4000", "localhost:8081"}
		for _, site := range sites {
			_, err := net.DialTimeout("tcp", site, timeout)
			if err != nil {
				t.Errorf("Integration site %+v unreachable: %+v\n***Disabling further integration tests***", site, err)
				*runIntegrations = false
			}
		}
	}
}

/**
 * Test that GET injections work with real vulnerable services. Requires that the expected test servers are running on localhost:4000
**/
var IntegrationBooleanJSGETValues = []struct {
	name            string
	url             string
	injectionsFound int
}{
	{"Correct param", "http://localhost:4000/user/lookup?username=guest", 1},
	{"Incorrect param", "http://localhost:4000/user/lookup?username=guester", 5},
	{"Empty param", "http://localhost:4000/user/lookup?username=", 5},
}

func TestIntegrationBooleanJSGET(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationBooleanJSGETValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.BlindBooleanInjectionTest(att)

				if len(injectables) != test.injectionsFound {
					t.Errorf("Mismatch in findings length\nGot: %+v findings. Expected: %+v\nGot: %#v\n", len(injectables), test.injectionsFound, injectables)
				}
			})
		}
	}
}

var IntegrationBooleanRegexGETValues = []struct {
	name             string
	url              string
	injectionsFound  int
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

func TestIntegrationBooleanRegexGET(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationBooleanRegexGETValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, "")
				injectables := scanners.BlindBooleanInjectionTest(att)

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
					if !found_param {
						t.Errorf("Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", param, test.url, injectables)
					}
				}
			})
		}
	}
}

/**
 * Test ability to inject mongo regex into POSTED paramters sent via JSON.
 */
var IntegrationBooleanRegexPOSTValues = []struct {
	name             string
	url              string
	body             string
	injectionsFound  int
	injectableParams []string
}{
	{"correct user param, incorrect password param", "http://localhost:4000/user/login", `{"username":"guest","password":"pass"}`, 2, []string{"guest", "pass"}},
	{"incorrect user param, incorrect password param", "http://localhost:4000/user/login", `{"username":"something","password":"pass"}`, 2, []string{"something", "pass"}},
	{"password == 'password'", "http://localhost:4000/user/login", `{"username":"something","password":"password"}`, 2, []string{"something", "password"}},
	{"username == 'username'", "http://localhost:4000/user/login", `{"username":"username","password":"pass"}`, 2, []string{"username", "pass"}},
}

func TestIntegrationBooleanRegexPOST(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationBooleanRegexPOSTValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, test.body)
				injectables := scanners.BlindBooleanInjectionTest(att)

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
					if !found_param {
						t.Errorf("Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", param, test.url, injectables)
					}
				}
			})
		}
	}
}

/**
 * Test ability to inject JS into POSTED paramters sent via JSON.
 */
var IntegrationBooleanJSPOSTValues = []struct {
	name             string
	url              string
	body             string
	injectionsFound  int
	injectableParams []string
}{
	{"correct user param", "http://localhost:4000/user/lookup", `{"username":"guest"}`, 1, []string{"guest"}},
	{"incorrect user param", "http://localhost:4000/user/lookup", `{"username":"something"}`, 4, []string{"something"}},
	{"Empty user param", "http://localhost:4000/user/lookup", `{"username":""}`, 4, []string{""}},
}

func TestIntegrationBooleanJSPOST(t *testing.T) {
	if *runIntegrations {
		for _, test := range IntegrationBooleanJSPOSTValues {
			t.Run(test.name, func(t *testing.T) {
				att := setup(t, test.url, test.body)
				injectables := scanners.BlindBooleanInjectionTest(att)

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
					if !found_param {
						t.Errorf("Missed Injectable parameter %+v with url %+v\nGot: %+v\n\n", param, test.url, injectables)
					}
				}
			})
		}
	}
}

/***********
 * Benchmarks
***********/

// See how long it takes to run all requests
func BenchmarkBooleanInjections(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
		}))
		defer ts.Close()

		url := ts.URL + "?param=value&param2=value2"
		var scanOptions = scanutil.ScanOptions{Target: url}
		att, _ := scanutil.NewAttackObject(scanOptions)

		scanners.BlindBooleanInjectionTest(att)
	}
}
