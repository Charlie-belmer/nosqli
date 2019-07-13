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
    "fmt"
    "net/url"
    "net/http"
    "io/ioutil"
    "log"
    "errors"
)

/**
 *  An object to manage attack payloads and structures. 
 */
type attackObject struct {
    URL *url.URL
    body string
}

type HTTPResponseObject struct {
    Url string
    Body string
    Header map[string][]string
    StatusCode int
}

func NewAttackObject(u string) attackObject {
   obj := attackObject{}
   obj.SetURL(u)
   obj.body = ""
   return obj
}

/**
 * Parse a URL into an attack object
 */
func (a *attackObject) SetURL(u string) {
	parsedURL, err := url.Parse(u)
    if err != nil {
        log.Fatal(err)
    }
    a.URL = parsedURL
}

/**
 *	Return a list of query parameters in a map param: value
 */
func (a *attackObject) QueryParams() map[string]string {
	q := a.URL.Query()
	m := map[string]string{}
	for k, v := range q {
		m[k] = v[0]
	}
	return m
}

/**
 * Change a query param in location paramLoc. Use this to 
 * attempt nosql injection via GET paramaters.
 */
func (a *attackObject) SetQueryParam(key string, payload string) {
    q := a.URL.Query()
    q[key][0] = payload
    a.URL.RawQuery = q.Encode()
}

/**
 * Update the request body with a payload
 */
func (a *attackObject) SetBody(body string) {
    
}

/**
 * Send a GET request to the object target
 */
func (a *attackObject) GET() (HTTPResponseObject, error) {
	url := a.URL.String()
	fmt.Printf("Running GET request for %s\n", url)
	obj := HTTPResponseObject{url, "", nil, 0}
    resp, err := http.Get(url)
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

/**
 * Send a POST request to the object target
 */
func (a *attackObject) POST() {

}