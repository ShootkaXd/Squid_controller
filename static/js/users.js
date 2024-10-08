function filterUsers() {
    const input = document.getElementById("searchInput");
    const filter = input.value.toUpperCase();
    const table = document.getElementById("usersTable");
    const tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) { // Начинаем с 1, чтобы пропустить заголовок
        const tdUsername = tr[i].getElementsByTagName("td")[5]; // Имя пользователя
        const tdIP = tr[i].getElementsByTagName("td")[1]; // IP-адрес

        if (tdUsername && tdIP) {
            const txtValueUsername = tdUsername.textContent || tdUsername.innerText;
            const txtValueIP = tdIP.textContent || tdIP.innerText;

            const isVisible = txtValueUsername.toUpperCase().includes(filter) || txtValueIP.toUpperCase().includes(filter);
            tr[i].style.display = isVisible ? "" : "none";
        }
    }
}

async function fetchNewUsers() {
    try {
        const response = await fetch('/get_new_users');
        const newUsers = await response.json();

        if (response.ok) {
            if (newUsers.length === 0) {
                console.warn('Нет новых пользователей для отображения.');
            }
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
    if (!newUsersTable) return; // Проверка существования элемента

    newUsersTable.innerHTML = '';

    newUsers.forEach(newUser => {
        const row = document.createElement('tr');
        row.dataset.mac = newUser.mac;
        row.innerHTML = `
            <td>${newUser.is_online}</td>
            <td>${newUser.ip}</td>
            <td>${newUser.mac}</td>
            <td>${newUser.hostname}</td>
            <td>${newUser.last_seen}</td>
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

async function saveChanges() {
   const usersTable = document.getElementById('usersTable');
   const rows = usersTable.querySelectorAll('tbody tr');

   const usersData = [];
   rows.forEach(row => {
       const cells = row.querySelectorAll('td');
       const userData = {
           is_online: cells[0].textContent,
           ip: cells[1].textContent,
           mac: cells[2].textContent,
           hostname: cells[3].textContent,
           last_seen: cells[4].textContent,
           username: cells[5].textContent,
           department: cells[6].textContent,
           cabinet: cells[7].textContent,
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

function toggleAccess(button, macAddress) {
    // Получаем текущий статус из data-атрибута
    var currentStatus = button.getAttribute('data-status') === 'true';

    $.ajax({
        type: 'POST',
        url: '/toggle_access',
        data: {
            macAddress: macAddress,
            currentStatus: currentStatus
        },
        success: function (response) {
            var newStatus = response.newStatus;

            // Обновляем текст кнопки
            button.innerText = newStatus ? 'доступ Запрещён' : 'доступ Разрешён';

            // Обновляем класс кнопки
            if (newStatus) {
                button.classList.remove('btn-primary');
                button.classList.add('btn-secondary');
            } else {
                button.classList.remove('btn-secondary');
                button.classList.add('btn-primary');
            }

            // Обновляем data-атрибут с новым статусом
            button.setAttribute('data-status', newStatus);
        },
        error: function (error) {
            console.error('Ошибка при обновлении статуса пользователя:', error);
        }
    });
}
//function setInitialAccessStatus() {
//    const users = document.querySelectorAll('#usersTable tbody tr');
//    users.forEach(userRow => {
//        const macAddress = userRow.querySelector('td').innerText;
//        const statusElement = userRow.querySelector(`#status_${macAddress}`);
//        const buttonElement = userRow.querySelector('button');
//        const currentStatus = statusElement.innerText === 'Разрешен';
//
//        statusElement.innerText = currentStatus ? 'Разрешен' : 'Запрещен';
//
//        buttonElement.innerText = currentStatus ? 'Запретить доступ' : 'Разрешить доступ';
//
//        statusElement.style.backgroundColor = currentStatus ? 'green' : 'red';
//    });
//}

window.addEventListener('load', () => {
    fetchNewUsers();
    fetchUsers();
    setInitialAccessStatus();
});
