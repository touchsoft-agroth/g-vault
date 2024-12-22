function populate_password_table(container, passwords) {
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const tbody = document.createElement('tbody');

    const headerRow = document.createElement('tr');
    ['ID', 'Service', 'Password'].forEach(header => {
        const th = document.createElement('th');
        th.textContent = header;
        headerRow.appendChild(th);
    })
    thead.appendChild(headerRow);

    passwords.forEach(item => {
        const row = document.createElement('tr');
        [item.id, item.service_name, item.password_text].forEach(value => {
            const td = document.createElement('td');
            td.textContent = value;
            row.appendChild(td);
        });
        tbody.appendChild(row);
    })

    table.appendChild(thead);
    table.appendChild(tbody);

    container.appendChild(table);
}

document.addEventListener('DOMContentLoaded', function () {
    const passwordContainer = document.getElementById("password-table-container");
    const button = document.getElementById("load-passwords-button");

    button.addEventListener('click', async function(event) {
        event.preventDefault();

        try {
            const response = await fetch('api/password');
            const data = await response.json();
            passwordContainer.textContent = ""; // clears table
            populate_password_table(passwordContainer, data);
        } catch {

        }
    })
})