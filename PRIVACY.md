# Privacy policy

Data Cleaner is free, open-source software that you run yourself, on your own computer or server. This policy covers the software. It explains what an install of Data Cleaner does with your information, including the Google (Gmail) and Microsoft (Outlook) account access you give it.

## Who has your data

- **Only the install you run.** Data Cleaner has no central server, account system or cloud service. The project and its developers never receive your data, your email, or your Google or Microsoft account access.
- **Your own sign-in app.** Each install connects to Google or Microsoft through an OAuth app that the person running it creates in their own Google Cloud or Microsoft Entra account. Nobody else holds those credentials.
- **Encrypted on your machine.** Account tokens, the personal details you enter, and the replies Data Cleaner keeps are stored encrypted in the install's own database.
- **No telemetry.** Data Cleaner doesn't track you, show ads, or report usage.

## What Data Cleaner does with your Gmail or Outlook access

Data Cleaner asks for two permissions: to **send** email (Gmail `gmail.send`, Microsoft `Mail.Send`), and to **read** email (Gmail `gmail.readonly`, Microsoft `Mail.Read`). It uses them only for these features:

1. **Sending your requests.** It sends the data-removal requests and follow-ups you approve to data brokers, from your own address. If you set an alert address, it also sends summary emails to you.
2. **Reading broker replies.** It checks for new incoming messages (the first check looks back 30 days, Spam included, because broker replies often land there). It keeps only messages that answer one of its own requests, matched by email threading headers or a private reference code in the request. It uses them to update the request's status. It doesn't keep anything else it reads, except each message's ID, so it doesn't read the same message twice.
3. **Finding newsletters to unsubscribe from (only when you run it).** It reads only the From, Subject, Date and List-Unsubscribe headers of the last 60 days of mail. Then it lists the senders, so you can unsubscribe. It doesn't read message bodies for this.

Data Cleaner never:

- sells, rents or shares your Google or Microsoft data;
- uses it for advertising, profiling or credit decisions;
- uses it to train AI or machine-learning models;
- lets a person read it, apart from you and whoever runs your install.

The only time information leaves your install is when it carries out what you ask it to do. For example, a removal request goes to the broker it's addressed to.

Data Cleaner's use and transfer of information received from Google APIs adheres to the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy), including the Limited Use requirements.

## Other information you enter

To make removal requests and check for exposure, you enter details such as names, addresses, phone numbers and email addresses. Data Cleaner sends parts of them only where a feature needs them:

- **Removal requests** go to the data brokers they're addressed to.
- **People-search checks:** to see whether a people-search site lists you, Data Cleaner looks you up on that site.
- **Web searches** go through the install's own SearXNG, which passes them to public search engines with no account or cookies attached. If you add a Brave Search API key instead, they go to Brave.
- **Breach checks:** the email addresses and phone numbers you choose to monitor go to breach-check services. XposedOrNot and LeakCheck are on by default. Have I Been Pwned, GitHub code search and psbdmp are used only if you turn them on. Passwords are checked with k-anonymity, so only the first 5 characters of a hash leave your machine.

## Removing access and deleting data

- **Disconnect in Data Cleaner:** Settings → your mailbox → **Disconnect**. This revokes the access at Google and deletes the stored tokens.
- **Revoke at the provider:** for Google, use [Third-party apps & services](https://myaccount.google.com/connections). For Microsoft, use [Apps and services](https://account.live.com/consent/Manage).
- **Delete everything:** delete the install's data folder or Docker volume. Nothing is kept anywhere else.

## Changes and contact

Changes to this policy are published in this file, and its history is visible in the repository. For questions about how a particular install is run, contact the person who runs it. For questions about the software, open an issue at [github.com/FearInc4/Data-cleaner](https://github.com/FearInc4/Data-cleaner/issues). Report security problems as described in [SECURITY.md](SECURITY.md).
