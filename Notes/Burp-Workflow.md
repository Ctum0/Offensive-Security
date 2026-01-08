# Burp Suite – My Manual Testing Workflow

## Why I use Burp
I use Burp Suite to see and modify the HTTP requests sent from the browser to the server.  
This helps me understand how the application works and what inputs the server trusts.  
Burp is mainly used for manual testing, not automated scanning.

## Setting up Burp
I configure my browser to send traffic through Burp Proxy.  
I open Burp and enable interception so I can see requests in real time.  
Once setup is complete, I browse the application normally.

## Intercepting Requests
I intercept requests when performing actions such as logging in, submitting forms, or clicking buttons.  
Intercepting requests allows me to see the full HTTP request before it reaches the server.  
This helps identify parameters, cookies, and headers.

## What I Look For in Requests
I look for parameters that are controlled by the user, such as IDs, usernames, or hidden fields.  
I also check cookies and authorization headers to understand session handling.  
These areas are common places where security issues occur.

## Testing Requests with Repeater
Interesting requests are sent to Burp Repeater for manual testing.  
In Repeater, I modify one parameter at a time and resend the request.  
I compare responses to see if server behavior changes.

## Simple Example Test
For example, if a request contains a parameter like `role=user`, I may change it to `role=admin`.  
If the server accepts the change and grants extra access, it may indicate an authorization issue.  
This type of testing helps identify logic flaws.

## Key Takeaways
Burp Suite is most effective when used for manual testing and logical analysis.  
Understanding application behavior is more important than using automated tools.  
Small request changes can sometimes reveal serious security issues.