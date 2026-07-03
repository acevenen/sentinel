// INTENTIONALLY VULNERABLE demo file for Sentinel. Do not reuse.

// Hardcoded cloud credentials committed to source control.
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Renders untrusted input straight into the DOM — reflected XSS.
function showGreeting() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name");
  document.getElementById("greeting").innerHTML = "Welcome back, " + name + "!";
}

// Evaluates a user-supplied expression — arbitrary code execution.
function calculate(expression) {
  return eval(expression);
}

module.exports = { showGreeting, calculate, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
