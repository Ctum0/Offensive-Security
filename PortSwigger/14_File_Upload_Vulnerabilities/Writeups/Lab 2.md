# Web shell upload via path traversal
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Web shell upload via path traversal_
Vulnerability: _Unrestricted File Upload (Path Traversal Bypass)_

---
## DESCRIPTION
The application features a vulnerable file upload mechanism. Although the server correctly restricts script execution within the designated upload directory, an attacker can bypass this defense by chaining a path traversal vulnerability. By manipulating the filename parameter, the attacker forces the server to store a malicious PHP web shell in a higher-level directory where execution is permitted.

---
## ROOT CAUSE
The backend server explicitly prevents the execution of user-supplied files within the default user avatars directory but fails to sanitize the `filename` parameter during the upload process. This architectural oversight allows URL-encoded path traversal sequences (e.g., `..%2f`) to manipulate the final storage location of the uploaded file, circumventing the intended execution restrictions.

---
## ATTACK SCENARIO
- Generates a malicious PHP payload designed to read the contents of `/home/carlos/secret`.
- Initiates an avatar upload request using the malicious PHP script.
- Intercepts the outbound HTTP POST request.
- Modifies the `filename` parameter by prepending a URL-encoded path traversal sequence (e.g., `filename="..%2fexploit.php"`).
- Forwards the request, forcing the server to decode the sequence and save the file one directory level above the restricted upload folder.
- Navigates to the uploaded file's new path via an HTTP GET request, triggering the execution of the PHP script and extracting the secret token from the server response.

---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /my-account/avatar`
**Exploit Payload (`exploit.php`):**
```PHP
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
**Header Modification:**
```HTTP
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"
Content-Type: application/x-php
```

---
## IMPACT
This chains two distinct vulnerabilities to achieve Remote Code Execution (RCE). By bypassing intended execution restrictions, the attacker gains total control over the server environment, leading to unauthorized access to sensitive internal file systems.

---
## FIX / MITIGATION
Never implicitly trust the user-supplied `filename` parameter. Strip all directory traversal sequences (e.g., `../`, `..\`) from uploaded filenames. To permanently neutralize this vector, generate a randomized, collision-resistant string (such as a UUID) to rename the file entirely upon storage. Furthermore, ensure execution permissions are globally stripped across all user-writable directories, not just the default upload path.

---
## KEY LEARNING
Directory execution restrictions are entirely ineffective if the application allows path traversal in the filename parameter during the upload process.

---
