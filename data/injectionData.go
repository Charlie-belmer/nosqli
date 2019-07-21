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
package data

/**

TOOL CONSTANTS

**/
var Version string = "0.1"
var VersionName string = "Pre-Release Alpha"


/**

MONGO DATA

**/
var MongoSpecialCharacters = []string{ "'", "\"", "$", ".", ">", "[", "]" }
var MongoPrefixes = []string{ "'", "\"", }
var MongoErrorStrings = []string{ 
	`Uncaught MongoDB\\Driver\\Exception\\CommandException: unknown operator`,
	`(?i)MongoError`,
	`(?i)SyntaxError`,
	`(?i)unterminated string literal`,
}
//TODO: data to insert into GET keys like search[$gt]=h

/* data extraction payload resources:
 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
 https://packetstormsecurity.com/files/107999/Time-Based-Blind-NoSQL-Injection.html
 https://blog.rapid7.com/2014/06/12/you-have-no-sql-inj-sorry-nosql-injections-in-your-application/
 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
*/ 