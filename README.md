### Security Checklist for Web Developers

  ##### Securing authentication
 - [ ] Use HTTPS everywhere - protect all endpoints over SSL encryption
 - [ ] Sanitize user input - properly sanitize all user input to make sure it does not contain characters which can circumvent application logic
 - [ ] Store passwords using encryption - store passwords in the database using encryption like bcrypt to restrict retrieval of password in case of breach
 - [ ] Use protective password standards - force user to register using a strong password
 - [ ] Enforce rate-limiting - rate-limit all authentication requests to prevent brute-force attacks
 - [ ] Suppress verbose error messages - don’t print messages confirming the existence of user account, to prevent user enumeration
 - [ ] Provide unique, unpredictable usernames - if self-registration is disabled, don’t use easily guessable usernames, to prevent user enumeration
 - [ ] Unique password reset tokens - send completely encrypted/random password reset tokens which cannot be guessed by attacker
 - [ ] Expire password reset tokens - make sure the password reset token expires after a reasonable amount of time
 - [ ] Implement OAuth properly - prevent open redirects and use the state parameter in OAuth endpoints
 - [ ] Secure the HTTP responses for authentication-related requests - don’t leak the OTP / password / reset token in response to user’s requests
 - [ ] Secure JWT tokens - ensure secure use of JWT tokens by validating the algorithm and the signature on the backend
 - [ ] Secure ‘Forgot Password’ - don’t rely on user input like host header to generate reset tokens
 - [ ] Secure OTP handling and generation - generate minimum 6 digits OTP and make sure it is one-time use only
 - [ ] Protect against referer leakage - ensure that sensitive tokens like password reset tokens don’t get leaked via the referer header to third-party websites

  ##### Securing session management
 - [ ] Secure token generation - ensure that all session tokens are reasonably random, are not meaningful, and cannot be brute-forced
 - [ ] Proper cookie scope - tie the session tokens to only the subdomains which require them, using the domain and path flags
 - [ ] Use HttpOnly, secure and SameSite cookies - use these flags to ensure protection in case of client-side attacks like XSS and CSRF
 - [ ] Secure session termination - after user logout or password reset, kill all existing sessions of the user and invalidate all session tokens
 - [ ] Restrict disclosure of tokens in URLs - don’t disclose session tokens in URLs as they might be logged or sent as referer to third party websites
 - [ ] Prevent token reuse - ensure no session tokens are same for consecutive / concurrent logins

 
 
  ##### Securing access controls / authorization
 - [ ] Secure user identifiers - use RFC compliant UUIDs for every user account
 - [ ] Use JWT - prefer JWT over traditional session tokens for ease of securing
 - [ ] Secure static files - developers often forget securing access controls for static files like JPEG etc.
 - [ ] Secure multi-stage functions - properly enforce access controls over functions which require more than one level of user interaction, eg. directly accessing example.com/?step=3 without going through /?step=2 or /?step=1
 - [ ] Secure function names - don’t use identifier based functions eg. if an endpoint exists /?action=getUser, then attacker might be able to guess and endpoint like /?action=deleteUser
 - [ ] Secure access control methods - don’t rely on identifiers like URL parameter, referer headers, HTTP headers to check access level of user; check everything on backend also as client-side checks can be bypassed by user submitted input
 - [ ] Secure multi-layered access controls -  enforce proper access controls for accounts with different levels of privileges to prevent vertical privilege escalation

 
 
  #### Secure HTTP headers
 - [ ] Add CSP header - use this header in HTTP responses to prevent XSS and client-side injection attacks
 - [ ] Add CSRF header - use CSRF tokens in HTTP headers to prevent cross site request forgery
 - [ ] Add X-XSS-Protection header - use this with value set to 1; mode=block to mitigate XSS attacks
 - [ ] Add HSTS header - tells the browser to load website using only HTTP
 - [ ] Add X-Frame-Options - use this with value as sameorigin to prevent clickjacking attacks.
 - [ ] Use X-Content-Type-Options: nosniff - to prevent MIME sniffing by browser like IE, which can lead to XSS
 - [ ] Use correct Content-Type headers - the browser should not get confused between JSON, XML and HTML responses, as this inconsistency can also lead to injection attacks like XSS 
 - [ ] Use correct caching directives - to prevent caching of sensitive information

 
 
  #### Miscellaneous - best practices to follow when building applications
 - [ ] Validate, encode and sanitize all input in the backend, to prevent against injection attacks like XSS, SQL injection, template injection etc.
 - [ ] Use parameterized queries and prepared statements for building SQL queries in the backend
 - [ ] While input validation can be either whitelisted or blacklisted, it is preferable to whitelist data. Whitelisting only passes expected data. In contrast, blacklisting relies on programmers predicting all unexpected data
 - [ ] Disable directory listing
 - [ ] Properly configure CORS (wherever applicable) by using proper CORS headers i.e.  Access-Control-Allow-Origin, Access-Control-Allow-Methods etc.
 - [ ] Ensure proper egress filtering to minimize the damage of attacks like SSRF and data exfiltration using out-of-band channels
 - [ ] Make sure all stacks and modules used in development are updated
 - [ ] Don't print stack trace for error messages as they might contain sensitive server information
 - [ ] Use proxies like CloudFlare to protect your website against most attacks, and also to hide the true origin IP of web server
 - [ ] Use proper caching directives to prevent caching of sensitive user info, and also to prevent against attacks like HTTP request smuggling
 - [ ] Don’t leak server info like server version, PHP version etc. in HTTP response as attacker might use this to get publicly available exploits for vulnerable versions
 - [ ] Use DMARC and SPF records in DNS servers - to protect against email spoofing attacks
 - [ ] Ensure all unnecessary ports are closed and are not exposed to the internet
 - [ ] Make use of live monitoring and alerting provisions to detect targeted attacks and bad actors in real-time as quickly as possible
 - [ ] Don’t leave the staging environments exposed to the internet, and don't use live data for them
 - [ ] Check all subdomains for expiry, else they might be vulnerable to subdomain takeovers
