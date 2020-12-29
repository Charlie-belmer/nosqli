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
	"crypto/md5"
	"fmt"
	"bytes"
)

type InjectionType int

const (
	Blind = InjectionType(iota)
	Timed
	Error
	GetParam
)

func (it InjectionType) String() string {
	switch it {
	case Blind:
		return "Blind NoSQL Injection"
	case Timed:
		return "Timing based NoSQL Injection"
	case Error:
		return "Error based NoSQL Injection"
	case GetParam:
		return "Get Parameter NoSQL Injection"
	}
	return ""
}

/**
 *  An object to manage discovered injections.
 *   - AttackObject is the original (unmodified) request that a successful injection was discovered for.
 *   - InectableParam is the param to be replaced with an attack
 *   - InjectedParam is the final value of the param
 *   - InjectedValue is the final value given to the param
 *
 * Some injection types won't have both an injected param and value.
 */
type InjectionObject struct {
	Type            InjectionType
	AttackObject    AttackObject
	InjectableParam string
	InjectedParam   string
	InjectedValue   string
	Prefix			string
	Suffix 			string
}

func (i *InjectionObject) Print() {
	fmt.Print(i.String())
}

func (i *InjectionObject) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Found %s:\n\tURL: %s\n\tparam: %s\n\tInjection: %s=%s\n\n", i.Type, i.AttackObject.Request.URL, i.InjectableParam, i.InjectedParam, i.InjectedValue)
	return b.String()
}


/**
 * Return a hash of this object
 */
func (i *InjectionObject) Hash() string {
	serial := i.Type.String() + i.AttackObject.Request.URL.String() + i.InjectableParam  + i.InjectedParam + i.InjectedValue
	md5 := md5.Sum([]byte(serial))
	return string(md5[:])
}

/**
 * Remove any duplicate items in a slice of InjectionObjects
 */
func Unique(injections []InjectionObject) []InjectionObject {
	found := make(map[string]bool)
	var uniques []InjectionObject

	for _, injection := range injections {
		if !found[injection.Hash()] {
			uniques = append(uniques, injection)
		}
		found[injection.Hash()] = true
	}
	return uniques
}
