(function () {
    'use strict';

    function loadAdminRoles() {
        const token = localStorage.getItem('auth');

        fetch('/admin/roles', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Auth-Token': token
            }
        })
        .then(response => {
            if (response.status === 200) {
                return response.text();
            } else {
                throw new Error('Access denied');
            }
        })
        .then(html => {
            document.getElementById('main-content').innerHTML = html;
        })
        .catch(err => {
            alert('You do not have access to role management.');
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        const btnRoles = document.getElementById('btn-roles');
        if (btnRoles) {
            btnRoles.addEventListener('click', loadAdminRoles);
        }
    });

})();