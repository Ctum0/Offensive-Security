# Web shell upload via Content-Type restriction bypass
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Web shell upload via Content-Type restriction bypass_
Vulnerability: _Unrestricted File Upload (Content-Type Bypass)_

---
## DESCRIPTION
The application's avatar upload functionality contains an unrestricted file upload vulnerability. The system attempts to restrict file types but relies exclusively on the user-controllable `Content-Type` header. An attacker exploits this by manipulating the HTTP header to upload a malicious PHP web shell, achieving Remote Code Execution (RCE) to exfiltrate sensitive server files.

---
## ROOT CAUSE
The backend server implicitly trusts the `Content-Type` HTTP header supplied by the client during a `multipart/form-data` upload. It fails to perform secondary validation on the file's extension or internal signature (magic bytes), allowing executable scripts to bypass the intended image-only security control.

---
## ATTACK SCENARIO
- Generates a malicious PHP payload (`exploit.php`) designed to read the contents of the `/home/carlos/secret` directory.
- Initiates an avatar upload request using the malicious PHP file.
- Intercepts the outbound HTTP POST request.
- Modifies the `Content-Type` header from `application/x-php` to the permitted `image/png` MIME type.
- Forwards the manipulated request to the backend, successfully bypassing the validation check.
- Navigates to the uploaded file's URL via an HTTP GET request, triggering the execution of the PHP script and extracting the secret token from the server response.

---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /my-account/avatar`

**Exploit Payload (`exploit.php`):**
```PHP
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

**Header Modification:**
```HTTP
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/png
```

---
## IMPACT
This vulnerability directly leads to Remote Code Execution (RCE). An attacker can deploy web shells to gain complete control over the underlying operating system, resulting in the unauthorized extraction of sensitive internal data and total server compromise.

---
## FIX / MITIGATION
Implement a strict, mathematically defined allowlist for file extensions (e.g., strictly `.png` and `.jpeg`). Furthermore, validate both the `Content-Type` header and the file's internal magic bytes on the server side to mathematically ensure the uploaded file matches the expected image structure.

---
## KEY LEARNING
Never implicitly trust user-controllable HTTP headers for security validation; file uploads require strict server-side verification of extensions and internal file signatures.

---
