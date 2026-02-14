# Excessive trust in client-side controls
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Excessive trust in client-side controls_
Vulnerability: _Business Logic Flaw (Price Tampering)_

---
## DESCRIPTION
The application relies on client-submitted data to determine the price of an item during the purchasing workflow. A business logic flaw allows an attacker to intercept the request when adding an item to the shopping cart and arbitrarily modify the item's price.

---
## ROOT CAUSE
**Excessive Trust in Client Input:** The backend server fails to validate the `price` parameter submitted in the client's `POST` request against a trusted internal data source (such as the product database). It blindly processes the transaction based on the cost dictated by the user.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs in as a standard user with a limited account balance (`wiener`).
2. **Action:** The attacker selects the target item ("Lightweight l33t leather jacket") and clicks "Add to cart".
3. **Interception:** The attacker intercepts the `POST /cart` request using a web proxy.
4. **Tampering:** The attacker identifies the hidden `price` parameter and changes its value from the legitimate price to `1` (representing 1 cent or pence).
5. **Execution:** The attacker forwards the modified request to the server, proceeds to the cart, and completes the checkout process, successfully purchasing the item for a fraction of its actual cost.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /cart` endpoint 
**Payload:** `price=1`

---
## IMPACT
**High:** Financial loss and inventory theft. Attackers can purchase expensive goods for negligible amounts, directly impacting the business's revenue and stock.

---
## FIX / MITIGATION
1. **Server-Side Pricing Logic:** Never trust client-side input for critical transaction values like price, discount, or product availability.
2. **Data Integrity:** When adding an item to the cart or processing a checkout, the backend application must independently fetch the canonical price of the item from a secure, server-side database using only the `productId` and `quantity`.

---
## KEY LEARNING
**Hidden Fields Provide Zero Security.** Client-side controls, such as hidden HTML form fields (`<input type="hidden">`) or disabled UI elements, are trivial to bypass. All critical validation and pricing logic must be strictly enforced on the server.

---
