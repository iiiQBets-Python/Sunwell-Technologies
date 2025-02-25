document.addEventListener("DOMContentLoaded", function() {
    const inputs = document.querySelectorAll(".form-control, .form-select");
    inputs.forEach(input => {
        input.addEventListener("blur", function() {
            if (input.value) {
                input.classList.add("filled");
            } else {
                input.classList.remove("filled");
            }
        });

        // Initial check to handle pre-filled inputs
        if (input.value) {
            input.classList.add("filled");
        }
    });

    // Switch between Email and SMS forms
    const emailLink = document.getElementById('emailLink');
    const smsLink = document.getElementById('smsLink');
    const emailTab = document.getElementById('email');
    const smsTab = document.getElementById('sms');

    emailLink.addEventListener('click', function(event) {
        event.preventDefault();
        emailLink.classList.add('active');
        smsLink.classList.remove('active');
        emailTab.classList.add('show', 'active');
        smsTab.classList.remove('show', 'active');
    });

    smsLink.addEventListener('click', function(event) {
        event.preventDefault();
        smsLink.classList.add('active');
        emailLink.classList.remove('active');
        smsTab.classList.add('show', 'active');
        emailTab.classList.remove('show', 'active');
    });
});