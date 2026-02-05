# Reflected XSS with some SVG markup allowed
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Reflected XSS with some SVG markup allowed_
Vulnerability: _Reflected XSS (WAF Bypass via SVG Animation)

---
## DESCRIPTION
The application contains a search function protected by a WAF that blocks common HTML tags and event handlers. However, it fails to block specific SVG-related tags and attributes. This allows an attacker to inject an SVG animation element that triggers code execution immediately upon rendering.

---
## ROOT CAUSE
**Incomplete Denylist (SVG Context):** The WAF blocks standard vectors (`<script>`, `onload`) but permits the `<svg>`, `<animatetransform>`, and `onbegin` keywords. The developer likely overlooked the risk of SVG animation events executing JavaScript.

---
## ATTACK SCENARIO
1. **Fuzzing:**
    - The attacker fuzzes tags and finds `svg` and `animatetransform` return `200 OK`.
    - The attacker fuzzes attributes and finds `onbegin` returns `200 OK`.
2. **Analysis:** The `onbegin` event does not fire on the `<svg>` tag itself. It requires an animation element.
3. **Weaponization:** The attacker nests the payload:
    - `<svg>`: Initializes the SVG context.
    - `<animatetransform>`: Starts an animation node.
    - `onbegin=alert(1)`: Fires immediately when the animation starts (which is instantly). 
4. **Execution:** The payload is reflected. The browser parses the SVG, starts the animation, and executes the alert.

---
## PROOF OF CONCEPT
### Injection Point
- **URL Parameter:** `search`
- **Context:** HTML Body
### Payload Used
```html
<svg><animatetransform onbegin=alert(1)>
```
---
## IMPACT
**Medium:** Allows execution of arbitrary JavaScript without user interaction (Zero-Click). The reliance on SVG support is negligible as all modern browsers support it.

---
## FIX / MITIGATION
**Comprehensive Encoding:** HTML-encode all user input. If specific tags must be allowed, use a strict **Allowlist** that strips all attributes (especially event handlers like `onbegin`) rather than relying on a Denylist.

---
## KEY LEARNING
**Context-Specific Events.** Events like `onbegin` are useless on standard HTML tags (`div`, `body`). They only work in specific contexts (SVG Animations). A WAF might allow `onbegin` thinking it's harmless text, not realizing it's a valid execution vector inside an `<animatetransform>` tag.

---
