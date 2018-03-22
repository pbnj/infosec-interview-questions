# Information Security Interview Questions

> A collection for interview questions for Information Security roles

## Table Of Contents

<!-- vim-markdown-toc GFM -->

* [Application Security](#application-security)
* [Blue Team](#blue-team)
* [Encryption](#encryption)
* [Forensics](#forensics)
* [General](#general)
* [Incidence Response](#incidence-response)
* [Networking](#networking)
* [Red Team](#red-team)
* [Vulnerability Management](#vulnerability-management)
* [Where Credit is Due](#where-credit-is-due)

<!-- vim-markdown-toc -->

## Application Security

* If you had to both encrypt and compress data during transmission, which would you do first, and why?

  * Compression aims to use patterns in data to reduce its size.
  * Encryption aims to randomize data so that it's uninterpretable without a secret key.
  * If you encrypt first, then compress, then your compression will be useless. Compression doesn't work on random data.
  * If you compress first, then encrypt, then an attacker can find patterns in message length (Compression Ratio) to learn something about the data and potentially foil the encryption (like CRIME)
  * Resources:
    * [Encrypt or Compress First?](https://blog.appcanary.com/2016/encrypt-or-compress.html)
    * [CRIME](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2012/september/details-on-the-crime-attack/)

* What could attackers do with HTTP Header Injection vulnerability?

  * Carriage returns and line feeds (or %0D & %0A) are means to an end that would allow attackers to control HTTP headers
  * Attackers could inject XSS via Referer header
  * Attackers could set cookie to a value known by the attacker (session fixation)
  * Attackers could redirect to a malicious server

* Describe the last program or script that you wrote. What problem did it solve?

  * Just looking for signs that the candidate has basic understanding of programming concepts and is at least able to write simple programs

* How would you implement a secure login field on a high traffic website where performance is a consideration?

  * TLS (regardless of performance) is a must
  * Also, reducing 3rd party library dependencies could improve performance and reduce security risks (https://hackernoon.com/im-harvesting-credit-card-numbers-and-passwords-from-your-site-here-s-how-9a8cb347c5b5)
  * Content-Security Policy (CSP) to enforce stricter execution rules around JS and CSS (https://en.wikipedia.org/wiki/Content_Security_Policy)
  * Subresource Integrity (SRI) to ensure only known, trusted resource files are loaded from 3rd-party servers/CDNs (https://en.wikipedia.org/wiki/Subresource_Integrity)

* What are the various ways to handle brute forcing?

  * Account Lockouts/timeouts
  * API rate limiting
  * IP restrictions
  * Fail2ban
  * ...etc

* What is Cross-Site Request Forgery? And how to defend against it?

  * When an attacker gets a victim's browser to make requests with the victim's credentials
  * Example: if an image tag (`<img>`) points to a URL with an associated action, e.g. https://foo.com/logout
  * Defense includes but are not limited to:
    * check origins header & referer header
    * check CSRF tokens or nonce

* What is Cross-Site Scripting? What are the different types of XSS? How to defend against XSS?

  * XSS is when attackers get victim's browsers to execute some code (usually JavaScript) within their browser
  * Traditionally, types have been categorized into *Stored* and *Reflected* XSS attacks.
    * Stored XSS is some code that an attacker was able to persist in a database and gets retrieved and presented to victims (e.g. forum)
    * Reflected XSS is usually in the form of a maliciously crafted URL which includes the malicious code. When the user clicks on the link, the code runs in their browser
  * Recently there has been discussions around DOM-based XSS, which occurs when attackers can control DOM elements, thus achieve XSS without sending any requests to the server
  * XSS categories tend to overlap, therefore it's much better to describe XSS in terms like *Server Stored XSS*, *Server Reflected XSS*, *Client Stored XSS* (e.g. stored DOM-based XSS), or *Client Reflected XSS* (e.g. reflected DOM-based XSS)
  * Defense includes:
    * Output encoding (more important)
    * Input validation (less important)

* How does HTTP handle state?

  * HTTP is stateless
  * State is stored in cookies

## Blue Team

## Encryption

* What's the difference between encoding, encryption, and hashing?

  * Encoding ensures message integrity. Can be easily reversible. Example: base64
  * Encryption guarantees message confidentiality. Reversible only using the appropriate decryption keys. Example: AES256
  * Hashing is a one-way function. Cannot be reversed. The output is fixed length and usually smaller than the input.

* Does TLS use symmetric or asymmetric encryption?

  * Both.
  * The initial exchange is done using asymmetric encryption, but bulk data encryption is done using symmetric. See next question for additional information.
  * Resources:
    * https://web.archive.org/web/20150206032944/https://technet.microsoft.com/en-us/library/cc785811.aspx
    * https://en.wikipedia.org/wiki/Transport_Layer_Security

* Describe the process of a TLS session being set up when someone visits a secure website.

  * Client sends `hello` message that lists cryptographic information, such as SSL/TLS version and the client's order of preference of cipher suites. The message also contains a random byte string that is used in subsequent calculations. Client may include data compression methods in the `hello` message as well.
  * Server responds with `hello` message that contains the cipher suite chosen by the server, the server's digital certificate, and another random byte string. If the server requires client certificate authentication, the server will also send `client certificate request` to the client.
  * Client verifies server's digital certificate.
  * Client sends a random byte string encrypted with the server's public key to allow both client and server to calculate the secret key used for subsequent encryption between client & server.
  * If server requested a client certificate, the client sends a random byte string encrypted with the client's private key with the client's digital certificate or "no digital certificate alert". This alert is only a warning, but some implementations will cause the handshake to fail if client authentication is mandatory.
  * Server verified client's digital certificate.
  * Client sends `finished` message encrypted with the calculated secret key
  * Server sends `finished` message encrypted with the calculated secret key
  * For the duration of the TLS session, the server and client can now exchange messages that are symmetrically encrypted with the shared secret key
  * Resources:
    * [An overview of the SSL or TLS handshake](https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.1.0/com.ibm.mq.doc/sy10660_.htm)

* How is TLS attacked? How has TLS been attacked in the past? Why was it a problem? How was it fixed?

  * [Weak ciphers](https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001))
  * [Heartbleed](http://heartbleed.com/)
  * [BEAST](https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat)
  * [CRIME](https://security.stackexchange.com/questions/19911/crime-how-to-beat-the-beast-successor/19914#19914)
  * [POODLE](https://censys.io/blog/poodle)

* What is Forward Secrecy?

  * Forward Secrecy is a system that uses ephemeral session keys to do the actual encryption of TLS data so that even if the server’s private key were to be compromised, an attacker could not use it to decrypt captured data that had been sent to that server in the past.

* Describe how Diffie-Hellman works.

## Forensics

## General

* Are open source projects more or less secure than proprietary projects?

  * Both models have pros and cons.
  * There are examples of insecure projects that have come out of both camps.
  * Open source model encourages "many eyes" on a project, but that doesn't necessarily translate to more secure products
  * What's important is not open source vs proprietary, but quality control of the project.

* Who do you look up to in the Information Security field? Why?

* Where do you get your security news from?

## Incidence Response

## Networking

## Red Team

## Vulnerability Management

## Where Credit is Due

* [Daniel Miessler's Blog](https://danielmiessler.com/study/infosec_interview_questions)

