# check-oss-index
Tooling for checking a list of dependencies against the [Sonatype OSS Index](https://ossindex.sonatype.org/)

This tool is designed to work against the CSV file that is output by [streeva/read-dependencies-go](https://github.com/streeva/read-dependencies-go) or [streeva/read-dependencies-action](https://github.com/streeva/read-dependencies-action)

You can provide a Bot User OAuth Access Token and the application will attempt to post message(s) about any vulnerabilities find to Slack via a custom bot.  Checks can be made against the OSS Index anonymously, but they are rate-limited, if you find you are getting told to back off by the service you can [sign-up for free](https://ossindex.sonatype.org/user/register) and this gives you an increase to the access limit.

## Usage
A pre-built Docker image is available publicly on GitHub Container Registry, which you can run as so:
```
docker run -it -v `pwd`:/workspace -w /workspace ghcr.io/streeva/check-ossindex:v1.1.0 [parameters]
```
### Arguments
```bash
Usage of ./check-ossindex:
  -i string
    	Specify input file name
  -s string
    	Slack access token
  -t string
    	OSS Index access token. Default is unauthenticated
  -u string
    	OSS Index username. Default is unauthenticated
```

## Input CSV File format
```
<Source manifest file name>,<Package Management Ecosystem>,<Package Name>,<Package Version>
```
E.g.
```
streeva.csproj,NuGet,Microsoft.CodeAnalysis.CSharp,3.7.0
```

## Build
Clone the repo
```
git clone git@github.com:streeva/check-ossindex-go.git

cd check-ossindex-go
```
Build the application
```
go build
```
Run directly
```
./check-ossindex
```
Or build the Docker image
```
docker build . -t check-ossindex
```