# Zoom Rivet for JavaScript

Zoom Rivet is a comprehensive toolkit built to help developers quickly integrate and manage server-side applications within the Zoom ecosystem. This tool currently supports Node.js, offering core functionalities like authentication, API wrappers, and event subscriptions, enabling developers to focus on business logic instead of infrastructure.

## Getting started

### Installation

In your Node.js application, install the Zoom Rivet package:

```
$ npm install @zoom/rivet
```

### Initialization

You can import and initialize the client from any [supported module](https://developers.zoom.us/docs/rivet/#modules) using the pattern for the Chatbot module in the code snippet below.

In a new entrypoint file called `index.js`, add the following code, replacing `CLIENT_ID`, `CLIENT_SECRET`, and `WEBHOOK_SECRET_TOKEN` with your [Marketplace app](https://marketplace.zoom.us) credentials:

```javascript
import { ChatbotClient } from "@zoom/rivet/chatbot";

(async () => {
  const chatbotClient = new ChatbotClient({
    clientId: "CLIENT_ID",
    clientSecret: "CLIENT_SECRET",
    webhooksSecretToken: "WEBHOOK_SECRET_TOKEN"
  });

  // Zoom Rivet code goes here!

  const server = await chatbotClient.start();
  console.log(`Zoom Rivet Events Server running on: ${JSON.stringify(server.address())}`);
})();
```

Save your `index.js` file and run the following command to start your local development server:

```
$ node index.js
```

### Expose local development server

Now that your app runs on your local machine, let's use [ngrok](https://ngrok.com/) to allow Zoom to reach your server through webhook:

```
$ ngrok http 8080
```

## Basic Concepts

To use Zoom Rivet effectively, you should understand three important concepts: authentication, listening to events, and using the Web API.

### Authentication

Zoom Rivet handles authentication for developers. All you have to do is provide your app's `ClientId` and `ClientSecret`. See the matrix in the table below to better how authentication works in each Rivet module:

| Supported Module | Auth Type                                                                                                                             |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Accounts         | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Chatbot          | [Client Credentials](https://developers.zoom.us/docs/team-chat-apps/installation-and-authentication/#authentication)                  |
| Commerce         | [Server OAuth](https://developers.zoom.us/docs/internal-apps/)                                                                        |
| Marketplace      | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Meetings         | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Meetings         | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Phone            | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Team Chat        | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Users            | [User OAuth](<(https://developers.zoom.us/docs/integrations/)>) <br /> [Server OAuth](https://developers.zoom.us/docs/internal-apps/) |
| Video SDK        | [JSON Web Token (JWT)](https://developers.zoom.us/docs/video-sdk/api-request/)                                                        |

### Listening to Events

To listen to events sent to your app, you can use the `event()` method in the `webEventConsumer` property. This method can be used to listen to any supported Zoom webhook event, like a slash command shown below.

This method receives a required parameter of `string`, which filters out webhook events that do not match.

```javascript
chatbotClient.webEventConsumer.event("bot_notification", (response) => {
  const payload = response.payload;
  console.log(payload);
});
```

### Using the Web API

You can call any of the supported Zoom APIs using their respective methods in the `endpoints` namespace of the module's client.

See the following example of the `sendChatbotMessage()` API from the Chatbot module:

```javascript
const reqBody = {
  robot_jid: payload.robotJid,
  account_id: payload.accountId,
  to_jid: payload.toJid,
  user_jid: payload.userJid,
  content: {
    head: {
      text: "I am a header",
      sub_head: {
        text: "I am a sub header"
      }
    },
    body: [
      {
        type: "message",
        text: "I am a message with text"
      }
    ]
  }
};

chatbotClient.endpoints.messages.sendChatbotMessage({ body: reqBody }).then((response) => {
  console.log("SENT MESSAGE", response.data);
});
```

### Event shortcuts

Rivet provides built-in shortcuts that enable you to execute complex processes in just a few lines of code.

#### Chatbot

##### `onSlashCommand()`

Your app can use the `onSlashCommand()` method to listen to incoming slash command requests.
Use the `say()` method to respond to slash commands. It accepts a string or [App Card JSON](https://developers.zoom.us//docs/team-chat-apps/customizing-messages/).

```javascript
chatbotClient.webEventConsumer.onSlashCommand("SLASH_COMMAND", async ({ say, payload }) => {
  console.log(payload);
  await say("Hello World!");
});
```

##### `onButtonClick()`

Your app can listen to button clicks and respond using the `onButtonClick()` method. This method takes in a string, which filters button action values.
You can respond with the `say()` function, which accepts a string or [App Card JSON](https://developers.zoom.us//docs/team-chat-apps/customizing-messages/).

```javascript
chatbotClient.webEventConsumer.onButtonClick("BUTTON_VALUE", async ({ say, payload }) => {
  console.log(payload);
  await say("Hello World!");
});
```

#### Team Chat

##### `onChannelMessagePosted()`

You can use the `onChannelMessagePosted()` method to listen to messages that your app can receive.
You can use the `reply()` method to respond to slash commands. It accepts a string or App Card JSON.

```javascript
teamchatClient.webEventConsumer.onChannelMessagePosted("KEYWORD", async ({ reply, payload }) => {
  console.log(payload);
  await reply("Hello World!");
});
```

**For the full list of features and additional guides, see our [Zoom Rivet docs](https://developers.zoom.us/docs/rivet).**

## Sample Apps

- [Zoom Rivet for JavaScript sample app](https://github.com/zoom/rivet-javascript-sample)

## Need help?

If you're looking for help, try [Developer Support](https://developers.zoom.us/support/) or our [Developer Forum](https://devforum.zoom.us/). Priority support is also available with [Premier Developer Support](https://explore.zoom.us/en/support-plans/developer/) plans.
