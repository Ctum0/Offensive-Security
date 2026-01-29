# Server-Side Template Injection with a Custom Exploit
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Server-Side Template Injection with a Custom Exploit_

---
## DESCRIPTION
The application uses the **Twig** (PHP) template engine. It contains a "Preferred Name" functionality that is vulnerable to SSTI. Unlike previous labs where we executed generic shell commands, this environment is hardened. However, the application exposes a custom `user` object with methods that can be chained to achieve file deletion.

---
## ROOT CAUSE
**Insecure Object Exposure & Logic Flaw:**

1. **SSTI:** The application concatenates user input into a template string, allowing method invocation on available objects.
2. **Exposed Surface:** The `user` object is passed to the template context.
3. **Unsafe Method Logic:** The `user.setAvatar($path, $type)` method allows setting the avatar to _any_ local file path without validating it is an image. The `user.gdprDelete()` method blindly deletes the file at the path referenced by the avatar.
---
## ATTACK SCENARIO
1. **Discovery:** The attacker identifies SSTI in the "Preferred Name" field. Fuzzing reveals access to the `user` object.
2. **Source Code Review (via LFI):** By exploiting the `setAvatar` method to point to the source code (`/home/carlos/User.php`) and then retrieving it via the `/avatar` endpoint, the attacker reads the class definition.    
3. **Gadget Chain Construction:**
    - The `User` class has a `gdprDelete()` method that deletes `this->avatar`.
    - The `setAvatar()` method allows changing `this->avatar` to an arbitrary path.
4. **Exploitation (Two-Step):**
    - **Step 1:** Inject `user.setAvatar('/home/carlos/.ssh/id_rsa', 'image/jpg')`. When rendered, this points the user's avatar to the target SSH key.
    - **Step 2:** Inject `user.gdprDelete()`. When rendered, this deletes the file currently set as the avatar (the SSH key).
5. **Trigger:** The attacker loads a page containing their username (e.g., a blog post comment) to execute the template logic.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/my-account/change-blog-post-author-display`
- **Parameter:** `blog-post-author-display`
- **Method:** POST (Stored SSTI)
### Payload Used
Payload 1 (Point to Target):
```php
user.setAvatar('/home/carlos/.ssh/id_rsa', 'image/jpg')
```
Payload 2 (Execute Delete):
```php
user.gdprDelete()
```
### Retrieval Point
The success is confirmed by the lab banner turning green, indicating the file `.ssh/id_rsa` no longer exists.

---
## IMPACT
**High (Arbitrary File Deletion):** While full RCE was not achieved directly via shell commands, the attacker can delete critical system files (Availability Impact) or security credentials (like SSH keys), potentially locking out administrators or disabling security controls.

---
## FIX / MITIGATION
1. **Validation:** `setAvatar` should strictly validate that the input path is a valid uploaded image directory, not an absolute system path.
2. **Sanitization:** Do not allow arbitrary template expressions in the "Preferred Name" field.
3. **Privilege Separation:** The web user should not have permission to modify or delete files in `/home/carlos/.ssh/`.

---
## KEY LEARNING
- **Custom Gadgets:** In hardened environments where `system()` or `exec()` are blocked, look for application-specific logic flaws. If you can control a "File Path" variable and trigger a "Delete" function, you have a primitive for Arbitrary File Deletion.
- **Source Code Disclosure:** SSTI can often be used as a Local File Inclusion (LFI) vulnerability first (to read source code) before escalating to destruction.

---
