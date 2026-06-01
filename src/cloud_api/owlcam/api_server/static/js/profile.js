// Dark mode toggle logic
function setDarkMode(enabled) {
    if (enabled) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    localStorage.setItem('theme', enabled ? 'dark' : 'light');
}

function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
        const isDark = !document.body.classList.contains('dark-mode');
        setDarkMode(isDark);
    });
    // Load preference
    const saved = localStorage.getItem('theme');
    if (saved === 'dark') setDarkMode(true);
    else setDarkMode(false);
}

window.addEventListener('DOMContentLoaded', initThemeToggle);

document.getElementById('changePasswordForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const msgDiv = document.getElementById('changePasswordMsg');
    msgDiv.textContent = '';
    msgDiv.className = 'msg';

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        msgDiv.textContent = 'New passwords do not match.';
        msgDiv.classList.add('error');
        return;
    }
    if (newPassword.length < 6) {
        msgDiv.textContent = 'Password must be at least 6 characters.';
        msgDiv.classList.add('error');
        return;
    }

    try {
        const token = localStorage.getItem('auth');
        const response = await fetch('/profile/change_password', {
            method: 'POST',
            headers: {
                'X-Auth-Token': token,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        const data = await response.json();
        if (response.ok) {
            msgDiv.textContent = 'Password changed successfully!';
            msgDiv.classList.add('success');
            document.getElementById('changePasswordForm').reset();
        } else {
            msgDiv.textContent = data.error || 'Failed to change password.';
            msgDiv.classList.add('error');
        }
    } catch (err) {
        msgDiv.textContent = 'Error: ' + err.message;
        msgDiv.classList.add('error');
    }
});

document.getElementById('deleteAccountForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    if (!window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        return;
    }
    const msgDiv = document.getElementById('deleteAccountMsg');
    msgDiv.textContent = '';
    msgDiv.className = 'msg';
    user_id = document.body.getAttribute('profileID');

    try {
        const response = await fetch('/admin/users/' + encodeURIComponent(user_id), {
            method: 'DELETE',
            headers: {
                'X-Auth-Token': localStorage.getItem('auth'),
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (response.ok) {
            msgDiv.textContent = 'Account deleted successfully. Redirecting to signin...';
            msgDiv.classList.add('success');
            setTimeout(() => window.location.href = '/login', 2000);
        } else {
            msgDiv.textContent = data.error || 'Failed to delete account.';
            msgDiv.classList.add('error');
        }
    } catch (err) {
        msgDiv.textContent = 'Error: ' + err.message;
        msgDiv.classList.add('error');
    }
});

window.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('auth');
    const res = await fetch('/api/profile', {
        headers: { 'X-Auth-Token': token }
    });
    if (res.ok) {
        const data = await res.json();
        document.getElementById('profileUsername').textContent = data.username;
        document.getElementById('profileImg').src = data.profile_picture;
        document.body.setAttribute('profileID', data.user_id);
    } else {
        window.location.href = '/login';
    }
    const backBtn = document.getElementById('back-to-cameras');
    if (backBtn) {
        backBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = '/cameras';
        });
    }
});