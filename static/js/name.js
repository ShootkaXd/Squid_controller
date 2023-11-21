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

            // Check if the filter text matches either username or IP
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
        // Clear existing rows
        newUsersTable.innerHTML = '';

        // Add new rows based on the received data
        newUsers.forEach(newUser => {
            const row = document.createElement('tr');
            row.dataset.mac = newUser.mac;  // Set the MAC address as a data attribute
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

    // Call fetchNewUsers to populate newUsersTable when the page loads
    window.addEventListener('load', () => {
        fetchNewUsers();
        fetchUsers(); // Populate the main users table as well
    });

async function saveChanges() {
        const usersTable = document.getElementById('usersTable');
        const rows = usersTable.querySelectorAll('tbody tr');

        // Iterate through the rows and collect data for each user
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

        // Now you can send the usersData to the server using fetch or another method
        // For example:
        const response = await fetch('/update_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                users: usersData,
            }),
        });

        // Check the response and handle accordingly
        if (response.ok) {
            console.log('Changes saved successfully!');
        } else {
            console.error('Failed to save changes.');
        }
    }

function toggleAccess(checkbox) {
    const isChecked = checkbox.checked;
    const macAddress = checkbox.parentElement.parentElement.dataset.mac;

    // Toggle the access status locally
    const accessStatus = isChecked ? 'Галочка' : 'Крестик';
    updateAccessStatus(macAddress, accessStatus);

    // Update the access status in the database via Socket.IO
    socket.emit('toggle_access', {'mac': macAddress, 'access': accessStatus});
}

function updateAccessStatus(mac, access) {
    // Update the access status locally
    const tableCell = document.querySelector(`#usersTable td[data-mac="${mac}"]`);
    if (tableCell) {
        tableCell.textContent = access;
    }
}
});