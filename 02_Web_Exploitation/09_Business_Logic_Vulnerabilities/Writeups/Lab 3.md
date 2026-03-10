# High-level logic vulnerability
---
## TARGET
PortSwigger Web Security Academy  
Lab: _High-level logic vulnerability_
Vulnerability: _Business Logic Flaw (Negative Quantity Injection)_

---
## DESCRIPTION
The application's shopping cart logic fails to adequately validate user input, specifically the `quantity` parameter. It does not enforce a minimum positive integer constraint. This allows an attacker to inject negative quantities of items into their cart, which mathematically deducts from the total cart price, allowing the purchase of expensive items for a fraction of their cost or completely free.

---
## ROOT CAUSE
**Missing Server-Side Input Validation:** The backend application calculates the total price by multiplying the item's unit price by the user-supplied quantity and summing the results. Because the system accepts negative integers for `quantity`, the arithmetic operation results in a negative cost being added to the cart, effectively subtracting from the total balance.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs into the application with standard credentials (`wiener`).
2. **Target Selection:** The attacker adds the high-value target item (Lightweight l33t leather jacket, `productId: 1`, quantity `1`) to the cart.
3. **Exploitation:** The attacker intercepts the request to add a cheaper, secondary item (`productId: 2`) and modifies the `quantity` parameter to a negative integer (e.g., `-39`).
4. **Bypass:** The application accepts the negative quantity. The total cart price drops from $1337.00 to an amount within the attacker's available store credit (e.g., under $100.00).
5. **Execution:** The attacker proceeds to checkout, successfully purchasing the high-value item with the manipulated cart total.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /cart` 
**Payload (Retrieval):**
```HTTP
productId=2&redir=PRODUCT&quantity=-39
```

---
## IMPACT
**High:** Direct financial loss and inventory theft. The flaw allows malicious actors to manipulate the pricing engine and steal high-value physical or digital goods.

---
## FIX / MITIGATION
1. **Strict Type & Range Validation:** Enforce server-side validation on the `quantity` parameter. Ensure it is cast as an integer and strictly strictly evaluate that `quantity > 0` before processing the cart addition.
2. **State Verification:** Implement checks at the checkout phase to verify that the final calculated total matches the expected sum of all individual items, and that no item quantities are zero or negative.

---
## KEY LEARNING
**Never Trust Client Math.** Arithmetic operations on the backend must account for edge cases, including negative numbers, zero, and integer overflows. Always constrain numeric inputs to their expected logical boundaries.

---
