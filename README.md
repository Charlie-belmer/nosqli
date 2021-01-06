# NoSQL Injector [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/share?text=NoSQLi%20Injection%20Security%20Scanner&url=https://github.com/Charlie-belmer/nosqli&hashtags=nosql,infosec)
![Header Img](https://nullsweep.com/content/images/2020/12/NoSQLi.png)
A fast NoSQL scanner and injector. For finding sites vulnerable to NoSQL injection, Mongo in particular.

## About Nosqli
I wanted a better nosql injection tool that was simple to use, fully command line based, and configurable. To that end, I began work on nosqli - a simple nosql injection tool written in Go. 

It aims to be fast, accurate, and highly usable, with an easy to understand command line interface.

## Features
Nosqli currently supports nosql injection detection for Mongodb. It runs the following tests:
 * Error based - inject a variety of characters and payloads, searching responses for known Mongo errors
 * Boolean Blind injection - inject parameters with true/false payloads and attempt to determine if an injection exists
 * Timing injection - attempt to inject timing delays in the server, to measure the response.

## Installation

[Download the latest binary version](https://github.com/Charlie-belmer/nosqli/releases) for your OS, and install it in your path, or run from a local folder.

## Roadmap
I plan to add data extraction features. If you would like to see other features or configuration options, please open a pull request or issue!

## Using nosqli
It should be self-documented by simply running the command and reading the help files.

```bash
$ nosqli
NoSQLInjector is a CLI tool for testing Datastores that 
do not depend on SQL as a query language. 

nosqli aims to be a simple automation tool for identifying and exploiting 
NoSQL Injection vectors.

Usage:
  nosqli [command]

Available Commands:
  help        Help about any command
  scan        Scan endpoint for NoSQL Injection vectors
  version     Prints the current version

Flags:
      --config string       config file (default is $HOME/.nosqli.yaml)
  -d, --data string         Specify default post data (should not include any injection strings)
  -h, --help                help for nosqli
  -p, --proxy string        Proxy requests through this proxy URL. Defaults to HTTP_PROXY environment variable.
  -r, --request string      Load in a request from a file, such as a request generated in Burp or ZAP.
  -t, --target string       target url eg. http://site.com/page?arg=1
  -u, --user-agent string   Specify a user agent

Use "nosqli [command] --help" for more information about a command.

$ nosqli scan -t http://localhost:4000/user/lookup?username=test
Running Error based scan...
Running Boolean based scan...
Found Error based NoSQL Injection:
  URL: http://localhost:4000/user/lookup?=&username=test
  param: username
  Injection: username='
```

 You can test the tool using my vulnerable node js app, or other nosql injection labs.

## Building from source

If you prefer to build from source, or there isn't a compiled binary for your platform, you can do so by cloning the repository, installing dependencies, and building the project manually. This will require a recent Go version, and the appropriate GOPATH environment variable.

```bash
$ git clone https://github.com/Charlie-belmer/nosqli
$ cd nosqli
$ go get ./..
$ go install
$ nosqli -h
```

## Running Tests
There is a decent test suite included. Unit tests along with simple injection coverage can be run by using go test from the root directory:
```bash
go test ./...
```

Integration tests are also available which run injections against known vulnerable apps running locally. To use integration tests, install and run the [vulnerable nodejs Mongo injection app](https://github.com/Charlie-belmer/vulnerable-node-app) and my [vulnerable PHP lab fork](https://github.com/Charlie-belmer/nosqlilab) from [digininja](https://digi.ninja/projects/nosqli_lab.php). Then pass in the integrations flag:
```bash
go test ./... -args -integrations=true
```
If either environment is not found, integration tests will be disabled by one of the test cases, to speed the test run.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for discussion.

### Contributors License
Unless you specify otherwise, it is understood that you are offering the nosqli project the unlimited, non-exclusive right to reuse, modify, and relicense the code you contribute. This project will always be available Open Source, but this is important because the inability to relicense code has caused devastating problems for other Free Software projects (such as KDE and NASM). If you wish to specify special license conditions of your contributions, just say so when you send them.
