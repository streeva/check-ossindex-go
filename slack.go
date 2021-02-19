package main

import (
	"fmt"
	"github.com/slack-go/slack"
)

type Attachment struct 
{
	Heading   		string
	Content   		string
	SidebarColour string
	Link					string
}

func SendSlackMessage(token string, message string, attachments []Attachment) {
	var api = slack.New(token)

	params := slack.GetConversationsParameters{}
	channels, _, err := api.GetConversations(&params)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	var slackAttachments []slack.Attachment
	for _, attachment := range attachments {
		slackAttachments = append(slackAttachments, slack.Attachment{
			Title: 		attachment.Heading,
			Color:   		attachment.SidebarColour,
			Text:    		attachment.Content,
			TitleLink:	attachment.Link,
		})
	}

	for _, channel := range channels {
		if channel.IsMember {
			fmt.Println(channel.Name + " - " + channel.ID)
			_, timestamp, err := api.PostMessage(
				channel.ID,
				slack.MsgOptionText(message, false),
				slack.MsgOptionAttachments(slackAttachments...),
				slack.MsgOptionAsUser(true),
			)
			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}
			fmt.Printf("Message successfully sent to channel %s at %s", channel.Name, timestamp)
		}
	}
}