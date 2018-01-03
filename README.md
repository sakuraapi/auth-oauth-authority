# Introduction

Plugin handles oAuth Authentication.

# Facebook

See: https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow

Your application is responsible for "Logging People In".

The plugin is responsible for the section in "Confirming Identity".

Helpful resources:
* https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow
* https://developers.facebook.com/docs/facebook-login/access-tokens/#apptokens
* https://developers.facebook.com/docs/facebook-login/access-tokens/debugging-and-error-handling
* https://developers.facebook.com/docs/facebook-login/testing-your-login-flow


Steps:
(1) Your application calls: GET `https://www.facebook.com/v2.11/dialog/oauth?client_id={clientId}redirect_uri={redirect}&scope=email&auth_type=rerequest&state={UUID}`
    
* `clientId` is your Facebook App ID
* `redirect` is the path in your app facebook should call upon login
* `scope` is the list of rights you are asking for permission to access: https://developers.facebook.com/docs/facebook-login/permissions/
* `auth_type` set this to `rerequest`, which prompts the user to choose the scope they'll accept each time -- otherwise, if they denied email on a prior attempt (which will lead to a login failure) and you reprompt them, their prior scope permissions will be remembered.
* `state` is unique nounce to guard against cross-site requests (just make sure you actually check it on the way back)
  
   
For desktop / mobile native applications (including things like Ionic Framework), you might want to consider using `https://www.facebook.com/connect/login_success.html` as your `redirect_uri`.

If you are experimenting, drop the url into your browser with te develop console open to the network tab. You'll; get a `log_success.html`. Look at the "Headers" tab and at the bottom you'll see the query string parameters, under which you should see `code`.

(2) You will get back a response with parameters:

* `code`: your temporary key which you'll pass to the server
* `state`: the state you passed to facebook - verify this matches what you're expecting

Alternatively, you'll get an error response:
```
YOUR_REDIRECT_URI?
 error_reason=user_denied
 &error=access_denied
 &error_description=The+user+denied+your+request.
```

(3) Your app should then `POST /auth/oauth/login` with the body:
```
{
  "authority":"facebook",
  "domain":"org domain - this is optional",
  "token":"the code from (2) above"
}
```

(4) The server will exchange the code for an authorization token and will perform a user create and/or login

* The token will be used to pull the user's profile
* If the user does not exist, s/he will be created and logged in
* If the user already exists (there's a domain/email combination that matches), s/he will be logged in

(5) A JWT token dictionary will be returned to the client (just like with `auth-native-authority`. 

* If the user is newly created, s/he will have the `isNew` flag set to true in their resulting JWT(s).
* `isNew` state is only present on the user creation authentication, the state is not persisted anywhere so use it or lose it.

# Contributing
[![CLA assistant](https://cla-assistant.io/readme/badge/sakuraapi/auth-oauth-authority)](https://cla-assistant.io/sakuraapi/auth-oauth-authority)

* Sign the Contributor License Agreement (CLA)
* Fork the project; make your contribution (don't forget to write your unit-tests); do a pull request back to develop (pull updates frequently to not fall too far behind)
* Before heading off to work on something, considering collaborating first by either (1) opening an issue or (2) starting a conversation on gitter or in the Google forum that leads to back to (1)
* All work should be done against an issue (https://github.com/sakuraapi/auth-oauth-authority/issues)
* All contributions require unit-tests
* Use the linter (npm run lint) to verify you comply with the style guide
