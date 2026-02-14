# Low-level logic flaw
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Low-level logic flaw_
Vulnerability: _Business Logic Flaw (Integer Overflow)_

---
## DESCRIPTION
The application calculates the total price of a user's shopping cart using a 32-bit signed integer. It fails to implement proper bounds checking when multiple high-quantity items are added. By intentionally overloading the cart with a specific number of items, an attacker can exceed the maximum positive value of a 32-bit integer (2,147,483,647), causing the value to overflow and wrap around into a large negative number.

---
## ROOT CAUSE
**Unsafe Integer Arithmetic:** The backend programming language uses fixed-size integers for financial calculations without detecting or preventing overflow conditions. When the total cart value (in cents) surpasses the 32-bit limit, the most significant bit flips, resulting in a negative cart total.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker notes the target item costs $1337.00.
2. **Overload:** The attacker sends 324 sequential `POST` requests, adding 99 jackets each time.
3. **Precision Strike:** The attacker sends one final request adding exactly 47 jackets, breaching the 32-bit limit and forcing the cart total to exactly `-$1221.96`.
4. **Stabilization:** The attacker adds 26 units of a $48.05 filler item to bring the cart total to a valid $27.34.
5. **Execution:** The attacker checks out, successfully purchasing over 32,000 leather jackets for a fraction of the cost of one.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /cart` **Payload Strategy:**
1. Send `productId=1&redir=PRODUCT&quantity=99` (x324 times)
2. Send `productId=1&redir=PRODUCT&quantity=47` (x1 time)
3. Send `productId=7&redir=PRODUCT&quantity=26` (x1 time)

---
## IMPACT
**Critical:** Severe financial loss. Attackers can manipulate the core pricing engine to acquire unlimited inventory for virtually no cost.

---
## FIX / MITIGATION
1. **Use Safe Data Types:** Use arbitrary-precision integers or dedicated decimal data types that do not suffer from standard binary overflow.
2. **Strict Bounds Checking:** Implement server-side validation to ensure that the total price never exceeds a realistic maximum threshold and never falls below zero.

---
## KEY LEARNING
**Memory Limits dictate Logic Limits.** Financial logic is only as sound as the memory structures supporting it. Always account for binary constraints when calculating cumulative user inputs.

---
