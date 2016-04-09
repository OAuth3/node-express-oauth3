`/api/org.oauth3.consumer/authorization_redirect`
--------

The Facebook button on your website should open a popup window to this url in the format

`https://example-api.com/api/org.oauth3.consumer/authorization_redirect/facebook.com/browser_state=<<random-value>>`

Your server will store the browser state and save it to give back to you with the token later.

Eventually this should redirect back to

`https://example-frontend.com/oauth3.html#browser_state=<<same_value>>&token=some_tok`

Or

`https://example-frontend.com/oauth3.html#browser_state=<<same_value>>&error=some_err`

`/api/org.oauth3.consumer/authorization_code_callback`
----

Facebook will make a GET request to this URL with a code and a state.
Your server will respond with the code and
