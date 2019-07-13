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
    "net/http"
    "io/ioutil"
//    "net/url"
    "log"
    "errors"
)

type HTTPObject struct {
    Url string
    Body string
    Header map[string][]string
    StatusCode int
}

func Get(url string) (HTTPObject, error) {
    obj := HTTPObject{url, "", nil, 0}
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