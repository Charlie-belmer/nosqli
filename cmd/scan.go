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
package cmd

import (
    "fmt"
    "net/http"
    "io/ioutil"
    "github.com/spf13/cobra"
    "net/url"
    "log"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan endpoint for NoSQL Injection vectors",
    Long: `Scan an endpoint for NoSQL Injection vectors. This will return text 
specifying whether an injection was successfully found or not.

Examples:
    nosqli scan -u http://localhost/page?id=5`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("Running scan on %s...\n\n", target)
        baseline()
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
}

func baseline() {
    resp, err := http.Get(target)
    if err != nil {
        log.Fatal(err)
        return
    }

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(resp.Header)
    fmt.Println(string(body))
}



func subQueryString(url string, param string, sub string) {
    u, err := url.Parse(target)
    if err != nil {
        log.Fatal(err)
    }
    q := u.Query()
    //https://golang.org/pkg/net/url/#URL.Query
    //TODO: check that param exists, else return error
    //return updated URL with param replaced with sub.
}
/* Tests:
 - Check for error text in the response. Sample: 
 Fatal error: Uncaught MongoDB\Driver\Exception\CommandException: unknown operator: $ in /var/www/html/user_lookup.php:37 Stack trace: #0 /var/www/html/user_lookup.php(37): MongoDB\Driver\Manager->executeQuery('sans.users', Object(MongoDB\Driver\Query)) #1 {main} thrown in /var/www/html/user_lookup.php on line 37

 This is when GET param in PHP is given something like param[$invalid_operator]=text - since this passes an invalid operator in and mongo throws up.

 You can also have something like this:
 Exception: SyntaxError: unterminated string literal : functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:48:25
In file: /var/www/html/guess_the_key.php
On line: 48

when passing in a single or double quote as an argument. http://localhost:8080/guess_the_key.php?guess=%27%22%7B%7D#

In this one, it's direct JS injection, not really mongo injection per se.


Useful test list: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
*/