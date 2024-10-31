---
layout: post
title:  "BlueYard - TheTruth"
category: CD
---
{% include cd_blueyard.html title="TheTruth" difficulty="Hard" scenario="A recent transaction involving a credit card used for an illegal purchase on 19/12/2023 at 4:50 PM has been brought to the attention of the Cybercrime Investigation Unit. As a digital forensic investigator within this governmental agency, you've obtained a data dump from the suspect's Android phone following a legal warrant. The suspect, a graphic designer, denies any involvement, claiming they were at the airport at the time of the transaction. Your task is to analyze the data dump to determine the truth: Did the suspect use the credit card for the illegal transaction, or is another party involved? How was the credit card data compromised? Is there evidence of malware or other cybercriminal tools in this case? Your thorough investigation is critical to resolving this case." %}

# Questions

1. [Identify the suspect's friend he claims to have picked up from the airport. What is this friend's name?](#q1-identify-the-suspects-friend-he-claims-to-have-picked-up-from-the-airport-what-is-this-friends-name)
2. [To verify the suspect's airport visit, we need to locate the flight ticket. What's the flight number?](#q2-to-verify-the-suspects-airport-visit-we-need-to-locate-the-flight-ticket-whats-the-flight-number)
3. [To establish a timeline for the credit card transactions, can you provide the UTC timestamp of the last legitimate use of the credit card as per the suspect's browser data?](#q3-to-establish-a-timeline-for-the-credit-card-transactions-can-you-provide-the-utc-timestamp-of-the-last-legitimate-use-of-the-credit-card-as-per-the-suspects-browser-data)
4. [The suspect said he uses Discord and Gmail for communication. Can you identify the username of the suspicious contact who mentioned a specific email in a message.](#q4-the-suspect-said-he-uses-discord-and-gmail-for-communication-can-you-identify-the-username-of-the-suspicious-contact-who-mentioned-a-specific-email-in-a-message)
5. [Email is one of the most commonly used attack vectors, and knowing the sender's email address can be cross-referenced with other data sources for any related suspicious activity or can lead to discovering the attacker's identity. What is the sender's email address for the suspicious email received?](#q5-email-is-one-of-the-most-commonly-used-attack-vectors-and-knowing-the-senders-email-address-can-be-cross-referenced-with-other-data-sources-for-any-related-suspicious-activity-or-can-lead-to-discovering-the-attackers-identity-what-is-the-senders-email-address-for-the-suspicious-email-received)
6. [It appears the email was directing the suspect to download an APK file for design review. Can you determine the exact name of this APK file?](#q6-it-appears-the-email-was-directing-the-suspect-to-download-an-apk-file-for-design-review-can-you-determine-the-exact-name-of-this-apk-file)
7. [Knowing the malware family helps us understand its behavior, capabilities, and potential impact. What is the name of the malware family associated with the suspicious APK?](#q7-knowing-the-malware-family-helps-us-understand-its-behavior-capabilities-and-potential-impact-what-is-the-name-of-the-malware-family-associated-with-the-suspicious-apk)
8. [By analyzing the Command and Control (C2) server URL and associated network traffic, investigators can learn more about how the malware operates. What is the URL of the malware's C2 server?](#q8-by-analyzing-the-command-and-control-c2-server-url-and-associated-network-traffic-investigators-can-learn-more-about-how-the-malware-operates-what-is-the-url-of-the-malwares-c2-server)

# Discussion

Taken from the README.txt
> A recent transaction involving a credit card used for an illegal purchase on 19/12/2023 at 4:50 PM has been brought to the attention of the Cybercrime Investigation Unit. As a digital forensic investigator within this governmental agency, you've obtained a data dump from the suspect's Android phone following a legal warrant. The suspect, a graphic designer, denies any involvement, claiming they were at the airport at the time of the transaction. Your task is to analyze the data dump to determine the truth: Did the suspect use the credit card for the illegal transaction, or is another party involved? How was the credit card data compromised? Is there evidence of malware or other cybercriminal tools in this case? Your thorough investigation is critical to resolving this case.

Looks like we're going to be looking at an Android dump.

# Answering the Tasks

As with many other forensic investigations we can either use some of the utilities that will "do everything" or look at each artifact individually. I like to use a combination of both, so having Autopsy or ALEAPP running while I'm checking the artifacts.

Let's load up the `data` directory with Autopsy and select the aLEAPP ingest module. If there is data we find is missing, we can run the ingest module later.

`Autopsy -> New Case -> *Go through case creation* -> Logical Files -> Add data directory -> Deselect All, Select Android Analyzer (aLEAPP) -> Finish`

Once the Analyzer is done, we will proceed with viewing the data.

![Autopsy](/img/cd/blueyard/thetruth/q0_autopsy.png)

### Q1. Identify the suspect's friend he claims to have picked up from the airport. What is this friend's name?

The questions references some dialogue between two people, so we can make a qualified guess that the artifact is found within a messaging application.

Navigating to `Data Artifacts` and `Messages` reveals a message in the `mmssms.db` file:

![Q1 Answer](/img/cd/blueyard/thetruth/q1_sms.png)

{% include cd_flag.html id="1" description="Identify the suspect's friend he claims to have picked up from the airport. What is this friend's name?" flag="Shady" %}

### Q2. To verify the suspect's airport visit, we need to locate the flight ticket. What's the flight number?

It's likely that artifacts such as tickets would be stored as PDFs or images, so lets check the File View in Autopsy:

![Q2 File View](/img/cd/blueyard/thetruth/q2_fileview.png)

There are no PDFs, but there is afew pictures. If open the images we will find an image called `Plane Ticket.png` where the flight number is shown.

![Q2 Answer](/img/cd/blueyard/thetruth/q2_answer.png)

{% include cd_flag.html id="2" description="To verify the suspect's airport visit, we need to locate the flight ticket. What's the flight number?" flag="B 54321" %}

### Q3. To establish a timeline for the credit card transactions, can you provide the UTC timestamp of the last legitimate use of the credit card as per the suspect's browser data?

Noted in the README, the timestamp for the illegal purchase is `19/12/2023 at 4:50 PM` so the event must be before. We need to look at the browser data, and the ingest module we ran does not contain the necessary browser information. Let's load up DB Browser for SQLite and navigate to the Default profile in the data directory (`C:\Users\Administrator\Desktop\Start Here\Artifacts\data\data\com.android.chrome\app_chrome\Default`).

Most of the files are not with a file extension, so set the filter to All Files and open the `Web Data` file. If we then Browse data, and select the `credit_cards` table, we can see a timestamp under the `use_date`. This is stored in UNIX format, so we need to convert it which [CyberChef](https://cyberchef.org/#recipe=From_UNIX_Timestamp('Seconds%20(s)')&input=MTcwMjk0NDgyOA) can help us with.
![Q3 Answer](/img/cd/blueyard/thetruth/q3_timestamp.png)

{% include cd_flag.html id="3" description="To establish a timeline for the credit card transactions, can you provide the UTC timestamp of the last legitimate use of the credit card as per the suspect's browser data?" flag="19-12-2023 00:13:48" %}

### Q4. The suspect said he uses Discord and Gmail for communication. Can you identify the username of the suspicious contact who mentioned a specific email in a message.

Let's have a look at the artifacts for Discord, once again we need to open a database, which is stored in the `kv-storage` location in the Discord application folder (`C:\Users\Administrator\Desktop\Start Here\Artifacts\data\data\com.discord\files\kv-storage\@account.1185329177549873192`), the file named `a` is a database, with a table called `messages0`.

If we browse through the data, we find a message from a user regarding accepting a friend request. The message was received at `2023-12-18 23:26:49 UTC`.
![Q4 Answer](/img/cd/blueyard/thetruth/q4_answer.png)

{% include cd_flag.html id="4" description="The suspect said he uses Discord and Gmail for communication. Can you identify the username of the suspicious contact who mentioned a specific email in a message." flag="mysticshadow_0" %}

### Q5. Email is one of the most commonly used attack vectors, and knowing the sender's email address can be cross-referenced with other data sources for any related suspicious activity or can lead to discovering the attacker's identity. What is the sender's email address for the suspicious email received?

As described in Q4, we know we should be looking at Gmail, once again we can browse to the databases for gmail (`C:\Users\Administrator\Desktop\Start Here\Artifacts\data\data\com.google.android.gm\databases`) and access the `bigTopDataDB` file, in there we'll find a table called `items` with some blob that contains a message we're looking for.

![Q5 Answer](/img/cd/blueyard/thetruth/q5_answer.png)

{% include cd_flag.html id="5" description="Email is one of the most commonly used attack vectors, and knowing the sender's email address can be cross-referenced with other data sources for any related suspicious activity or can lead to discovering the attacker's identity. What is the sender's email address for the suspicious email received?" flag="john@numrent.com" %}

### Q6. It appears the email was directing the suspect to download an APK file for design review. Can you determine the exact name of this APK file?

If we keep looking at the same resource as previous question, we can scroll further down and find the URL that was linked to, in the email.

![Q6 URL](/img/cd/blueyard/thetruth/q6_link.png)

Then we navigate to the `History` database for Chrome (`C:\Users\Administrator\Desktop\Start Here\Artifacts\data\data\com.android.chrome\app_chrome\Default`), and access the Downloads table. In here we can see the download path, unfortunately it does not exist in the dump we have received.

![Q6 History](/img/cd/blueyard/thetruth/q6_downloads.png)

However, we can check the `external.db` (`C:\Users\Administrator\Desktop\Start Here\Artifacts\data\data\com.android.providers.media.module\databases`) file for references to files written to storage. In there we find the name for the APK, coincidentally also the name of the file without `.apk`.

![Q6 Answer](/img/cd/blueyard/thetruth/q6_answer.png)

{% include cd_flag.html id="6" description="It appears the email was directing the suspect to download an APK file for design review. Can you determine the exact name of this APK file?" flag="NumRent" %}

### Q7. Knowing the malware family helps us understand its behavior, capabilities, and potential impact. What is the name of the malware family associated with the suspicious APK?

We need to find the suspicious APK file, and looking at some of the common artifacts does not yield the expected results. However, we can search our dump for content with `Numrent`, so let's fire up powershell and recursively search for some content:

![Q7 Search](/img/cd/blueyard/thetruth/q7_search.png)

This gives us a location to check for an APK. We can then get a hash we can use to search various sites for, such as VirusTotal.
{% highlight powershell %}
PS C:\Users\Administrator\Desktop\Start Here\Artifacts> get-filehash data\app\~~sIAt6D9n0DhLMs3yGG-Rdw==\com.example.confirmcode-FPzER1iWROYkcvW1xvY9TA==\base.apk

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          6D34BC631310FCDB668E5D7F6AE528D34C1A4F8A8AE5ED2C8BA21D5F7252CF9B       C:\Users\Administrator\Desktop\Start Here\Artifacts\data\app\~~sIAt6D9n0DhLMs3yGG-Rdw==\com.example.confirmcode-FPzER1iWROYkcvW1xvY9TA==\base.apk
{% endhighlight %}

Searching [Virus Total](https://www.virustotal.com/gui/file/6d34bc631310fcdb668e5d7f6ae528d34c1a4f8a8ae5ed2c8ba21d5f7252cf9b/details) yields us some useful information. The Family label is what we are after.

![Q7 Answer](/img/cd/blueyard/thetruth/q7_answer.png)

{% include cd_flag.html id="7" description="Knowing the malware family helps us understand its behavior, capabilities, and potential impact. What is the name of the malware family associated with the suspicious APK?" flag="RATMilad" %}

### Q8. By analyzing the Command and Control (C2) server URL and associated network traffic, investigators can learn more about how the malware operates. What is the URL of the malware's C2 server?

Either, we can deduce this from the output when we searched for `NumRent`, we can use the intel from VirusTotal, or we can go all in and open the APK with `jadx`.
Once we have it opened with `jadx`, we can click `tools` and `decompile all classes` - give a few minutes, and we can browse to the application, `com.example.confirmcode` and check the `MainApplication` section, where a `Logger` function references the `serverURL` string.

![Q8 Answer](/img/cd/blueyard/thetruth/q8_answer.png)

{% include cd_flag.html id="8" description="By analyzing the Command and Control (C2) server URL and associated network traffic, investigators can learn more about how the malware operates. What is the URL of the malware's C2 server?" flag="api.numrent.shop" %}

