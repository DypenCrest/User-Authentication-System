var passwordInput = document.getElementById("password1");
var passwordStrengthMeter = document.getElementById("password-strength-meter");

passwordInput.addEventListener("input", function() {
    var password = passwordInput.value;
    var strength = zxcvbn(password).score;
    var labels = ["Very weak", "Weak", "Moderate", "Strong", "Very strong"];
    var label = labels[strength];
    var colorClasses = ["text-danger", "text-warning", "text-info", "text-success", "text-success"];
    var colorClass = colorClasses[strength];

    passwordStrengthMeter.innerText = label;
    passwordStrengthMeter.className = "form-text " + colorClass;
});
