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
	"github.com/Charlie-belmer/nosqli/data"
	"os"
)

/*
 *	Struct to store and manage scan options and defaults
 */
type ScanOptions struct {
	Target         string
	Request        string
	ProxyInput     string
	UserAgentInput string
	RequestData    string
	RequireHTTPS   bool
}

func (s *ScanOptions) Proxy() string {
	if s.ProxyInput == "" {
		return os.Getenv("HTTP_PROXY")
	} else {
		return s.ProxyInput
	}

}

func (s *ScanOptions) UserAgent() string {
	if s.UserAgentInput == "" {
		return fmt.Sprintf("NoSQLInjector: %s v%s", data.VersionName, data.Version)
	} else {
		return s.UserAgentInput
	}

}
