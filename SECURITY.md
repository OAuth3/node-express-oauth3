Brainstorming
=============

There are no known vulnerabilities that could lead to a data breach.

However, there are some issues that still need addressing.

Possible attack vectors:

* Place an arbitrarily large oauth3.json at a target and request login to that target
  * Limit download size of oauth3.json
* Cause many requests to many sites at oauth3.json
* Fill memory by requesting many sites with valid oauth3.json
* POST malformed data to `/api/oauth3/authorization_redirect`?
* GET/POST malformed data to `/api/oauth3/authorization_code_callback`?
* automatic registration could be invoked to gather developer emails or urls (an attacker visits logs into their own server from many sites, causing registration)

Non-issues

* `browser_state` doesn't need to be cryptographically random

Security

* No uses of `Math.random()`
