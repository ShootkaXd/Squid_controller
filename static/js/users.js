function filterUsers() {
    var input, filter, table, tr, tdUsername, tdIP, i, txtValueUsername, txtValueIP;
    input = document.getElementById("searchInput");
    filter = input.value.toUpperCase();
    table = document.getElementById("usersTable");
    tr = table.getElementsByTagName("tr");

    for (i = 1; i < tr.length; i++) {
        tdUsername = tr[i].getElementsByTagName("td")[2];  // Column index for username
        tdIP = tr[i].getElementsByTagName("td")[0];  // Column index for IP address

        if (tdUsername && tdIP) {
            txtValueUsername = tdUsername.textContent || tdUsername.innerText;
            txtValueIP = tdIP.textContent || tdIP.innerText;

            if (txtValueUsername.toUpperCase().indexOf(filter) > -1 || txtValueIP.toUpperCase().indexOf(filter) > -1) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = "none";
            }
        }
    }
}
async function fetchNewUsers() {
       try {
           const response = await fetch('/get_new_users');
           const newUsers = await response.json();

           if (response.ok) {
                updateNewUsersTable(newUsers);
           } else {
                console.error('Failed to fetch new users:', response.statusText);
           }
       } catch (error) {
            console.error('Error fetching new users:', error);
       }
}

    function updateNewUsersTable(newUsers) {
        const newUsersTable = document.getElementById('newUsersTable');
        newUsersTable.innerHTML = '';

        newUsers.forEach(newUser => {
            const row = document.createElement('tr');
            row.dataset.mac = newUser.mac;
            row.innerHTML = `
                <td>${newUser.ip}</td>
                <td>${newUser.mac}</td>
                <td contenteditable="true">${newUser.username}</td>
                <td contenteditable="true">${newUser.department}</td>
                <td contenteditable="true">${newUser.number_cabinet}</td>
                <td>
                    <button onclick="confirmAccess('${newUser.mac}')">Подтвердить доступ</button>
                </td>
            `;
            newUsersTable.appendChild(row);
        });
    }

    window.addEventListener('load', () => {
        fetchNewUsers();
        fetchUsers();
    });

async function saveChanges() {
        const usersTable = document.getElementById('usersTable');
        const rows = usersTable.querySelectorAll('tbody tr');

        const usersData = [];
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            const userData = {
                ip: cells[0].textContent,
                mac: cells[1].textContent,
                username: cells[2].textContent,
                department: cells[3].textContent,
                cabinet: cells[4].textContent,
            };
            usersData.push(userData);
        });


        const response = await fetch('/update_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                users: usersData,
            }),
        });

        if (response.ok) {
            console.log('Changes saved successfully!');
        } else {
            console.error('Failed to save changes.');
        }
    }

function toggleAccess(macAddress, currentStatus) {
    $.ajax({
        type: 'POST',
        url: '/toggle_access',
        data: {
            macAddress: macAddress,
            currentStatus: currentStatus
        },
        success: function (response) {
            var newStatus = response.newStatus;
            var statusElement = document.getElementById('status_' + macAddress);
            var buttonElement = statusElement.nextElementSibling.querySelector('button');

            statusElement.innerText = newStatus ? 'Разрешен' : 'Запрещен';

            buttonElement.innerText = newStatus ? 'Запретить доступ' : 'Разрешить доступ';

            statusElement.style.backgroundColor = newStatus ? 'green' : 'red';
            buttonElement.className = 'btn btn-action btn-sm ' + (newStatus ? 'btn-danger' : 'btn-success');
        },
        error: function (error) {
            console.error('Ошибка при обновлении статуса пользователя:', error);
        }
    });
}