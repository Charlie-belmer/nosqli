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
	"reflect"
)

type HTTPResponseObject struct {
	Url        string
	Body       string
	Header     map[string][]string
	StatusCode int
}

/**
 * Determine if a given response object is equal to this object.
 *
 * URL is not used in this determination. If two different URL's return the same
 * response code and body, they are considered equal. For instance a URL that includes
 * a boolean attack pattern may have differing URL's, and the same reponse, which can be used
 * to determine information from the server.
 */
func (this *HTTPResponseObject) ContentEquals(cmp HTTPResponseObject) bool {
	statusEquals := this.StatusCode == cmp.StatusCode
	bodyEquals := this.Body == cmp.Body
	return statusEquals && bodyEquals
}

/**
 * As Same as ContentEquals, but include headers in consideration
 */
func (this *HTTPResponseObject) DeepEquals(cmp HTTPResponseObject) bool {
	headerEquals := reflect.DeepEqual(this.Header, cmp.Header)
	return this.ContentEquals(cmp) && headerEquals
}