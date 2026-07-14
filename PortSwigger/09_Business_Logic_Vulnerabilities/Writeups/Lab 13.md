# Infinite money logic flaw
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Infinite money logic flaw_
Vulnerability: _Business Logic Vulnerability(Flaw in purchasing workflow)_

---
## DESCRIPTION
The application harbors a critical business logic vulnerability within its purchasing workflow, enabling financial arbitrage. Specifically, the system permits the application of percentage based promotional discount (SIGNUP30) to cash equivalent assets, such as gift cards. By systematically purchasing discounted gift cards and redeeming them at face value, an attacker can exploit this flaw to iteratively generate infinite store credit.

---
## ROOT CAUSE
The core deficiency is the failure to enforce domain specific business rules regarding promotional codes. The application lacks validation logic to exclude gift cards from percentage based discounts. Furthermore, the absence of rate limiting or state tracking allows an attacker to iteratively circumvent intended purchasing constraints without triggering security flags.

---
## ATTACK SCENARIO
1. Extracts the promotional code (SIGNUP30) from the newsletter subscription alert.
2. Adds a $10.00 gift card to the shopping cart and applies the promotional code, reducing the cost to $7.00.
3. Executes the purchase and retrieves the newly generated gift card redemption code.
4. Redeems the gift card into the account, netting a $3.00 profit per cycle
5. Automates this iterative sequence via a custom script to accumulate arbitrary amounts of store credit. 

---
## PROOF OF CONCEPT
**Execution Method:** Automated Python script utilizing `requests.Session()` to handle CSRF tokens and maintain session state.

**Transaction Math:** 
```
- Gift Card Face Value: $10.00
- Applied Discount (30%): -$3.00
- Purchase Price: $7.00
- Redemption Value: $10.00
- Net Profit per Iteration: $3.00
```

---
## IMPACT
This vulnerability is critical as it enables malicious actors o arbitrarily inflate their store credit. This results in severe financial loss and allows attackers to systematically drain inventory or acquire high value merchandise at zero net cost.

---
## FIX / MITIGATION
Implement strict server side validation to categorically exclude cash equivalent items (e.g., gift cards) from percentage based promotional discounts. Additionally, introduce rate limiting and robust state tracking to restrict the reuse of promotional codes.

---
## KEY LEARNING
Business logic validation must strictly govern the interaction between promotional discounts and cash equivalent assets to prevent financial arbitrage.

---
