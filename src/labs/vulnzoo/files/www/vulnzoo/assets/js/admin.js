document.addEventListener('DOMContentLoaded', function() {
    if (typeof currentDevice !== "null" && currentDevice !== null) {
        const container = document.getElementById('device-link-container');
        const btn = document.createElement('button');
        btn.className = 'btn';
        btn.textContent = 'Go to Device Page';
        btn.onclick = function() {
            window.location.href = `/pages/${currentDevice}.html`;
        };
        container.appendChild(btn);
    }
});


function showLogs() {
    var logsDiv = document.getElementById('logs');
    if (logsDiv && logsDiv.style.display === 'none') {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/cgi-bin/get-logs.sh', true);
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                document.getElementById('log-content').value = xhr.responseText;
                logsDiv.style.display = 'block';
            }
        };
        xhr.send();
    } else if (logsDiv) {
        logsDiv.style.display = 'none';
    }
}