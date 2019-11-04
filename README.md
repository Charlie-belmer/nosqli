# NoSQL Injector

NoSQL scanner and injector.

## About Nosqli
I wanted a better nosql injection tool that was simple to use, fully command line based, and configurable. To that end, I began work on nosqli - a simple nosql injection tool written in Go. 

It aims to be fast, accurate, and highly usable, with an easy to understand command line interface.

## Features
Nosqli currently supports nosql injection detection for Mongodb. It runs the following tests:
 * Error based - inject a variety of characters and payloads, searching responses for known Mongo errors
 * Boolean Blind injection - inject parameters with true/false payloads and attempt to determine if an injection exists

## Roadmap
Boolean based extraction is next on the list, followed by JavaScript injection, then timed injection attacks & data extraction.

## Using nosqli
It should be self-documented by simply running the command and reading the help files.

```bash
$ nosqli
NoSQLInjector is a CLI tool for testing Datastores that 
do not depend on SQL as a query language. 

The tool aims to be a simple automation tool for identifying and exploiting 
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

## Installation
To install the tool, install from source. Since I am rapidly making changes at this time, I haven't yet started distributing binaries. This will change once all core features are present (scan & extraction capabilities).

Clone the repository, install dependencies, and build the project

```bash
$ git clone https://github.com/Charlie-belmer/nosqli
$ cd nosqli
$ go get ./..
$ go install
$ nosqli -h
```

## Contributing
Contributions are welcome! Please submit a pull request, limiting changes to one logical change per pull request. 

### Contributors License
Unless you specify otherwise, it is understood that you are offering the nosqli project the unlimited, non-exclusive right to reuse, modify, and relicense the code you contribute. This project will always be available Open Source, but this is important because the inability to relicense code has caused devastating problems for other Free Software projects (such as KDE and NASM). If you wish to specify special license conditions of your contributions, just say so when you send them.