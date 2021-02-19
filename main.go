package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

const EXIT_SUCCESS = 0
const EXIT_FAILURE = 1

func check(e error) {
	if e != nil {
		fmt.Println(e)
		os.Exit(EXIT_FAILURE)
	}
}

func main() {
	var username string
	var token string
	var filename string
	var slacktoken string

	flag.StringVar(&username, "u", "", "OSS Index username. Default is unauthenticated")
	flag.StringVar(&token, "t", "", "OSS Index access token. Default is unauthenticated")
	flag.StringVar(&filename, "i", "", "Specify input file name")
	flag.StringVar(&slacktoken, "s", "", "Slack access token")
	flag.Parse()

	if len(filename) <= 0{
		fmt.Println("Please specify filename containing the dependency data")
		os.Exit(EXIT_FAILURE)
	}

	coordinatesMap := make(map[string]bool)
	file, err := os.Open(filename)
	check(err)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var segments = strings.Split(scanner.Text(), ",")
		if len(segments) < 4 {
			fmt.Println("Unexpected line in input file")
			os.Exit(EXIT_FAILURE)
		}

		coordinatesMap[fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(segments[1]), segments[2], segments[3])] = true
	}

	var coordinates []string
	for k := range coordinatesMap {
		coordinates = append(coordinates, k)
	}

	if len(coordinates) <= 0 {
		fmt.Println("No dependency data found in input file")
		os.Exit(EXIT_FAILURE)
	}

	var componentReports = CheckOssIndex(coordinates, username, token)
	for _, componentReport := range *componentReports {
		if len(componentReport.Vulnerabilities) <= 0 {
			continue
		}

		if len(slacktoken) > 0 {
			var attachments []Attachment
			for _, vulnerability := range componentReport.Vulnerabilities {
				attachments = append(attachments, Attachment { 
						Heading: 				fmt.Sprintf("%-10s %s",strings.ToUpper(GetSeverityClass(vulnerability.CVSSScore)), vulnerability.Title), 
						Content:				vulnerability.Description,
						SidebarColour:	GetSeverityColour(vulnerability.CVSSScore),
						Link:						vulnerability.Reference,
					})
			}

			SendSlackMessage(slacktoken, fmt.Sprintf("Vulnerabilities in project %s dependency <%s|%s>","blah",componentReport.Reference,componentReport.Coordinates), attachments)
		}
	}
}