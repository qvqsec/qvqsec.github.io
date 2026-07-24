---
title: "Unauthenticated Access to Member PII in a Sports Booking Platform"
date: 2026-07-24
categories: [blog]
---

## Introduction
This is a short story about how a simple misconfiguration can lead to serious personal data exposure. To set the scene, I was asked by a friend to make a booking on a sports platform, but whilst navigating the website I discovered something rather alarming.

I'll be honest, after clicking around for 10 seconds, I had a strong feeling it would contain some sort of security flaw. With my own personal data at stake, I deemed it necessary to look a little closer.

## Personal Data Exposure
When I logged into the platform, I found a dropdown menu `View` and found it interesting how there's a `Members` button. 

![Dropdown](/assets/img/dropdown.png)

As soon as the page loaded, I was surprised by the exposure, yet at the same time, not surprised at all. As a member, I was able to view the following information; Full names, Email Addresses and Phone numbers.

This appears to be a clear case of Broken Access Control.

![Members Directory](/assets/img/members1.png)

I asked myself, why on earth should I have access to all of this information? I got a little curious here, and wondered, can anyone see this?

## It Gets Worse
Next, I logged out of my members account and appeared to be at the main homepage of the booking system.

![Home](/assets/img/unauth1.png)

What if I could somehow access that members page, even without the navigation buttons available?

> Disclaimer:
> This is what I meant by simple misconfiguration 😄

I navigated directly to the exposed endpoint `frm<REDACTED>.aspx` and discovered there were no server-side authorisation controls restricting access to the page.

![Members Unauthenticated](/assets/img/unauth2.png)

This is a classic example of relying on "Security through obscurity" by hiding the navigation link from unauthenticated users, rather than enforcing authorisation checks in the backend.

Here's a heavily redacted screenshot exposing my own details.

![My Details Exposed](/assets/img/jord.png)

![Noo](/assets/img/noo.png)

## More Exposure
After this discovery, I wondered whether other clubs hosted on the same platform were also affected. Since the domain structure indicated a multi-tenant SaaS application, I used a Google dork (`site:"*.redacted.com"`) to discover other tenant subdomains.

Sure enough I found many other clubs affected and was able to confirm this, however the interface is the exact same, so I'll not repeat the redacted screenshot 😃

![Google Dork](/assets/img/dork.png)

Approximately 8 clubs were affected, exposing thousands of members' PII to anyone who knew or discovered the endpoint through various methods.

## Responsible Disclosure
The hosting provider had no official way of disclosing vulnerabilities. I was able to find the company name via the booking system, and then find the IT Manager's email.

I explained the situation honestly to them:

```
Hi <REDACTED>,

I am writing to responsibly disclose a broken access control vulnerability in <REDACTED> that exposes member personal data (name, email, mobile number) to unauthenticated users.

I found this vulnerability whilst attempting to book <REDACTED> at <REDACTED>, it was something I was not looking for, but rather stumbled upon.

First, I clicked "View" and selected "Members", this exposed the endpoint "<REDACTED>.aspx". See attached screenshots.

I tested whether this endpoint was accessible without authentication. Logging out and navigating directly to <REDACTED>.aspx returned the same personal data with no login required. See attached screenshot.

I then checked a <REDACTED> booking site hosted on the same platform, and confirmed the same vulnerability is present there. See attached screenshot for <REDACTED>.

Impact:
This allows any unauthenticated user to view personal data belonging to members of <REDACTED>. Given the number of sites affected on this platform, exposure may be significant, and this may breach data protection depending on your hosting arrangements.

Note:
I have not accessed, modified, or retained any member data beyond what was necessary to verify this issue.

I'd appreciate confirmation this email has been received, given the sensitivity of data involved. If you need anything, please let me know.

Kind regards,
Jordan Todd
```

To which, 30 minutes later I received the following reply:

```
Hi Jordan,

A quick update: the access-control gap you reported is now fixed. All affected pages require a valid login, and member data is fully secured. Thank you again for reporting this so responsibly; it allowed us to act fast.

We are also rolling out a newly rebuilt booking platform to clubs over the next few weeks. Security has been designed into this new system from the ground up to prevent issues like this by default.

Thanks again for pointing this out. 

Kind regards,

<REDACTED>
```

## Patch
After receiving confirmation of the fix, I tested the endpoint again, both as an unauthenticated user and from a member account, confirming that access was now properly restricted.

![401 Server Error](/assets/img/401.png)

Satisfied that the PII was secured and knowing the vendor was actively migrating to a redesigned platform, I decided it would not be necessary to poke around further.

## Conclusion
Simple misconfigurations often carry the highest real-world risk. Relying on hidden UI elements instead of server-side authorisation checks left hundreds, maybe thousands, of members' PII completely exposed.

The company responded swiftly, patching the issue within 30 minutes and communicated transparently. I appreciate the company being so upfront and thankful for the finding.

Seeing how a simple oversight could impact so many users was a huge eye opener. It’s motivated me to start exploring bug bounty platforms, and explore web application security more.

![Honest Work](/assets/img/honest.png)
