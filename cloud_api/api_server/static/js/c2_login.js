document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('authForm');
    const errorMsg = document.getElementById('errorMsg');
    if (!form) return;

    form.onsubmit = async function(e) {
        e.preventDefault();
        errorMsg.style.display = 'none';

        const code = document.getElementById('authInput').value;
        let payload;
        try {
            payload = JSON.parse(code);
        } catch (err) {
            payload = { panel_password: code };
        }

        try {
            const res = await fetch('/api/c2/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            if (res.ok && data.success) {
                window.location.href = data.redirect;
            } else {
                errorMsg.innerText = data.error;
                errorMsg.style.display = 'block';
            }
        } catch (err) {
            errorMsg.innerText = 'Network error. Try again.';
            errorMsg.style.display = 'block';
        }
    };
});