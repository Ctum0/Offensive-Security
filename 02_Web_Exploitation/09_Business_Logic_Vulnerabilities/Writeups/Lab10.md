# Insufficient workflow validation
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Insufficient workflow validation_
Vulnerability: _Business Logic Flaw (Forced Browsing / State Machine Bypass)_

---
## DESCRIPTION
The application's purchasing workflow is vulnerable to forced browsing. It assumes users will follow the intended sequence of steps (Cart → Checkout → Order Confirmation). By skipping the checkout and payment phase and directly accessing the order confirmation endpoint, an attacker can purchase items without having sufficient funds.

---
## ROOT CAUSE
**Lack of State Validation:** The server relies on the client's navigational sequence rather than strictly validating the transaction's state on the backend. It fails to verify if the "Payment Processed" state was actually achieved before honoring the request to execute the "Order Confirmation" state.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs in with standard user credentials.
2. **Target Selection:** The attacker adds an item to their cart that exceeds their available account balance.
3. **Bypass:** The attacker intentionally ignores the `/cart/checkout` endpoint.
4. **Execution:** The attacker forces the workflow forward by navigating directly to `/cart/order-confirmation?order-confirmed=true`.
5. **Fulfillment:** The application assumes previous steps were completed and processes the order, delivering the item.

---
## PROOF OF CONCEPT
**Injection Point:** `GET /cart/order-confirmation` 
**Payload:** `?order-confirmed=true` 
**Retrieval:** HTTP 200 OK and a successful order completion message without any deduction of required funds.

---
## IMPACT
**High:** Direct financial loss. Attackers can completely bypass payment gateways to acquire goods or services for free.

---
## FIX / MITIGATION
1. **Server-Side State Management:** Implement a robust finite-state machine (FSM) for business workflows. The server must track the user's progress through the checkout phases using a secure, server-side session object.
2. **State Verification:** Before executing the order confirmation logic, the backend must cryptographically verify that the payment state is marked as "Successful" or "Completed" in the database.

---
## KEY LEARNING
**Never trust the client's workflow sequence.** Clients can request any accessible endpoint at any time in any order. Workflows must be strictly enforced on the server by validating the prerequisite conditions for every sensitive action.

---
