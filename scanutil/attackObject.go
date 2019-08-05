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

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

/**
 *  An object to manage attack payloads and structures.
 */
type AttackObject struct {
	Request      *http.Request
	Client       *http.Client
	Options      ScanOptions
	Body         string
	originalBody string   // Keep the original body, so we can reset it after injecting attack strings.
	BodyValues   []string // List of all values that can be updated. May include maps or arrays (if body is JSON) - but as Strings
}

func NewAttackObject(options ScanOptions) (AttackObject, error) {
	attackObj := AttackObject{}

	if options.Request != "" {
		attackObj = parseRequest(options.Request)
	} else if options.Target != "" {
		var err error
		attackObj.Request, err = http.NewRequest("", options.Target, nil)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		return attackObj, errors.New("You must specify either a target or a request file to scan.")
	}

	if options.RequestData != "" {
		attackObj.SetBody(options.RequestData)
	}

	attackObj.Options = options
	attackObj.addClient()
	attackObj.Request.Header.Set("User-Agent", options.UserAgent())
	return attackObj, nil
}

func parseRequest(file string) AttackObject {
	obj := AttackObject{}
	fh, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	data := bufio.NewReader(fh)
	obj.Request, err = http.ReadRequest(data)
	if err != nil {
		log.Fatal(err)
	}

	// Update the request to make sure it is properly formed
	obj.Request.RequestURI = ""
	obj.Request.URL, err = url.Parse("http://" + obj.Request.Host + obj.Request.URL.String())
	if err != nil {
		log.Fatal(err)
	}
	obj.addClient()

	buf := new(bytes.Buffer)
	buf.ReadFrom(obj.Request.Body)
	obj.Body = buf.String()
	obj.originalBody = obj.Body
	obj.extractUpdateableValuesFromBody()

	return obj
}

/**
 *	Add a default client object to the attack object
 */
func (a *AttackObject) addClient() {
	proxy := a.Options.Proxy()
	transport := &http.Transport{}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.Fatal("Proxy not set correctly: %s", err)
		}
		fmt.Printf("Using proxy %s\n", proxyURL)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	a.Client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

/**
 * Parse a URL into an attack object
 */
func (a *AttackObject) SetURL(u string) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		log.Fatal(err)
	}
	a.Request.URL = parsedURL
}

/**
 *	Return a list of query parameters in a map param: value
 */
func (a *AttackObject) QueryParams() map[string]string {
	q := a.Request.URL.Query()
	m := map[string]string{}
	for k, v := range q {
		m[k] = v[0]
	}
	return m
}

/**
 * Change a query param in the request query string. Use this to
 * attempt nosql injection via GET paramaters.
 */
func (a *AttackObject) SetQueryParam(key string, payload string) {
	q := a.Request.URL.Query()
	q[key][0] = payload
	a.Request.URL.RawQuery = q.Encode()
}

/**
 * Remove an oldkey/value pair, and replace it with a new key value pair
 */
func (a *AttackObject) ReplaceQueryParam(oldkey string, key string, value string) {
	q := a.Request.URL.Query()
	q.Del(oldkey)
	q.Add(key, value)
	a.Request.URL.RawQuery = q.Encode()
}

/**
 * Replace a pattern with an injection payload within body data, assuming the
 * data is form URL encoded.
 */
func (a *AttackObject) setBodyQueryParam(pattern string, payload string, replaceKey bool) error {
	u, err := url.ParseRequestURI("/?" + a.Body)
	if err != nil {
		return err
	}
	q := u.Query()
	for key, vSlice := range q {
		if replaceKey && key == pattern {
			q[payload] = vSlice
			delete(q, key)
		} else {
			for i, v := range vSlice {
				if url.QueryEscape(v) == pattern {
					vSlice[i] = payload
				}
			}
			q[key] = vSlice
		}
	}
	a.Body = q.Encode()
	return nil
}

/**
 * Replace part of the JSON object with a payload
 * The payload should be proper JSON as it will completely replace an existing element -
 * if the payload is a string, it should include double quotes, like `"payload"`, if an
 * object, include the full object notation such as `{"$ne": 1}`
 */
func (a *AttackObject) setBodyJSONParam(pattern string, payload string, replaceKey bool, index int) error {
	switch jsonType(pattern) {
	case "string":
		// string should be surrounded by double quotes
		pattern = `"` + pattern + `"`
		re := regexp.MustCompile(pattern)
		if index == -1 {
			a.Body = re.ReplaceAllLiteralString(a.Body, payload)
		} else {
			var newBody string
			components := re.Split(pattern, -1)
			for i, substring := range components {

				if i == index {
					newBody = newBody + substring + payload
				} else if i == len(components)-1 {
					newBody = newBody + substring
				} else {
					newBody = newBody + substring + pattern
				}
			}
			a.Body = newBody
		}
	case "number", "boolean", "null":
		// objects that are not enclosed with quotes should always be values (not keys)
		// and thus prefixed with a colon or object opener and zero or more spaces
		// they also should be followed by a comma, or closure of an array or object.
		pattern = `(?P<Prefix>[\[,:]\s*?)(?P<Payload>` + pattern + `)(?P<Suffix>\s*?[,\]\}])`
		re := regexp.MustCompile(pattern)
		submatches := re.FindAllStringSubmatch(a.Body, -1)
		names := re.SubexpNames()
		m := map[string]string{}
		m2 := []map[string]string{}
		// If we have multiple matches, they may have differing prefixes and suffixes
		// so we'll go through and create a new regex and payload to exact match each.
		for _, submatch := range submatches {
			m = make(map[string]string)
			for i, n := range submatch {
				m[names[i]] = n
			}
			m2 = append(m2, m)
		}
		var newRegex string
		var newPayload string
		for _, finding := range m2 {
			newRegex = finding["Prefix"] + finding["Payload"] + finding["Suffix"]
			newPayload = finding["Prefix"] + payload + finding["Suffix"]
			re = regexp.MustCompile(newRegex)
			a.Body = re.ReplaceAllLiteralString(a.Body, newPayload)
		}

	default:
		// array or object should be ok as-is, just use string replace
		if index >= 0 {
			//a.Body = strings.Replace(a.Body, pattern, payload, index+1)
			var newBody string
			components := strings.Split(a.Body, pattern)
			for i, substring := range components {
				if i == index {
					newBody = newBody + substring + payload
				} else if i == len(components)-1 {
					newBody = newBody + substring
				} else {
					newBody = newBody + substring + pattern
				}
			}
			a.Body = newBody
		} else {
			a.Body = strings.ReplaceAll(a.Body, pattern, payload)
		}
	}
	return nil
}

/**
 * Find a pattern in the body, and replace it with the given payload.
 * If the body is JSON, this will take into account proper ways of finding
 * the data correctly. For instance, a string should always be surrounded by quotes,
 * but an int should be surrounded by some combination of white space, commas, or object/array
 * closures.
 *
 * This function assumes the pattern being replaced is a complete object - for instance
 * if the body contains '"key": "value"', we would only replace "key" or "value", but never
 * "alue"
 *
 * Only replaces keys if inKey is set to true, so that data like username=username can be
 * injected one at a time (key injections are rare) (not used on JSON at this time).
 *
 * Index will replace the <index>th instance of pattern. index = -1 -> replace all, 0 -> replace the first instance.
 */
func (a *AttackObject) ReplaceBodyObject(pattern string, payload string, replaceKey bool, index int) {
	if a.bodyIsJSON() {
		a.setBodyJSONParam(pattern, payload, replaceKey, index)
	} else {
		a.setBodyQueryParam(pattern, payload, replaceKey)
	}
	a.Request.ContentLength = int64(len(a.Body))
}

func (a *AttackObject) bodyIsJSON() bool {
	contentType := a.Request.Header.Get("Content-Type")
	return contentType == "application/json"
}

/**
 * Update the request body with a payload
 */
func (a *AttackObject) SetBody(body string) {
	a.Body = body
	a.originalBody = body

	if a.Body == "" {
		a.Request.Method = "GET"
		return
	} else {
		a.Request.Method = "POST"
	}

	if isJSON(a.Body) {
		a.Request.Header.Set("Content-Type", "application/json")
	} else {
		a.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		a.urlEncodeBody()
		a.originalBody = a.Body
	}
	a.extractUpdateableValuesFromBody()
	a.Request.ContentLength = int64(len(a.Body))
}

/**
 * URL encode a body to it matches application/x-www-form-urlencoded
 * content type.
 */
func (a *AttackObject) urlEncodeBody() {
	u, err := url.ParseRequestURI("/?" + a.Body)
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	a.Body = q.Encode()
}

/**
 * Replace attack body with original (default) data
 */
func (a *AttackObject) RestoreBody() {
	a.Body = a.originalBody
	a.Request.ContentLength = int64(len(a.Body))
}

/**
 * Pull out any values we might want to replace with injection strings,
 * and save them into the attack object.
 */
func (a *AttackObject) extractUpdateableValuesFromBody() {
	if isJSON(a.Body) {
		a.BodyValues = FlattenJSON(a.Body)
	} else {
		a.BodyValues = extractUpdateableQueryValuesFromBody(a.Body)
	}
}

func extractUpdateableQueryValuesFromBody(body string) []string {
	var values []string
	u, err := url.ParseRequestURI("/?" + body)
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	for k, v := range q {
		values = append(values, k)
		for _, val := range v {
			values = append(values, val)
		}
	}
	return values
}

/**
 * Update the request body with the body on the object.
 * Encode if a query string is used.
 */
func (a *AttackObject) setRequestBody() {
	a.Request.Body = ioutil.NopCloser(strings.NewReader(a.Body))
}

/**
 * Send the request to the object target
 */
func (a *AttackObject) Send() (HTTPResponseObject, error) {
	a.setRequestBody()
	url := a.Request.URL.String()
	obj := HTTPResponseObject{url, "", nil, 0}

	resp, err := a.Client.Do(a.Request)

	if err != nil {
		log.Fatal(err)
		return obj, errors.New("Unable to retrieve url")
	}

	obj.Header = resp.Header
	obj.StatusCode = resp.StatusCode

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return obj, errors.New("Unable to read response body")
	}

	obj.Body = string(body)

	return obj, nil
}
