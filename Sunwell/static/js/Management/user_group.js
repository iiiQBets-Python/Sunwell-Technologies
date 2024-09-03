//form script

document.getElementById('commGroup').addEventListener('change', function () {
    var commGroupValue = this.value;
    var departmentSelect = document.getElementById('departmentName');
    var options = departmentSelect.querySelectorAll('option');

    console.log('CommGroup Selected:', commGroupValue);

    options.forEach(option => {
        console.log('Option:', option.value, 'CommGroup:', option.dataset.commgroup);
        if (option.value === "") {
            option.style.display = "block";
        } else if (option.dataset.commgroup === commGroupValue) {
            option.style.display = "block";
        } else {
            option.style.display = "none";
        }
    });

    departmentSelect.disabled = !commGroupValue;  // Enable or disable based on selection
    departmentSelect.value = ""; // Reset the selection
});







// floating labels
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
  });
  // form select multiple slection
  document.addEventListener("DOMContentLoaded", function() {
    const accessibleDepartmentSelect = document.getElementById('accessibleDepartment');
    const selectedDepartmentsDiv = document.getElementById('selectedDepartments');

    function updateSelectedDepartments() {
        const selectedOptions = Array.from(accessibleDepartmentSelect.selectedOptions);
        selectedDepartmentsDiv.innerHTML = ''; // Clear existing selected items

        selectedOptions.forEach(option => {
            const selectedItem = document.createElement('div');
            selectedItem.className = 'selected-item d-inline-block me-2 mb-2 p-1 bg-light border rounded';
            selectedItem.innerHTML = `
                ${option.textContent}
                <button type="button" class="btn-close btn-close-sm" aria-label="Remove"></button>
            `;
            selectedDepartmentsDiv.appendChild(selectedItem);

            // Add event listener to remove button
            selectedItem.querySelector('.btn-close').addEventListener('click', () => {
                option.selected = false;
                updateSelectedDepartments();
            });
        });
    }

    accessibleDepartmentSelect.addEventListener('change', updateSelectedDepartments);
});

//table script
document.addEventListener("DOMContentLoaded", function() {
    const searchBar = document.getElementById('searchBar');
    const roleFilterDropdown = document.getElementById('roleFilterDropdown');
    const roleFilterItems = document.querySelectorAll('.role-filter .dropdown-item');
    const formDataTable = document.getElementById('form-data-table');
    const tableRows = Array.from(formDataTable.querySelectorAll('tr'));
    const visibleEntries = document.getElementById('visible-entries');
    const totalEntries = document.getElementById('total-entries');
    const pagination = document.querySelector('.pagination');
    const selectAllCheckbox = document.getElementById('selectAll');
    const entriesPerPageSelect = document.getElementById('entriesPerPage');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');

    let currentPage = 1;
    let entriesPerPage = parseInt(entriesPerPageSelect.value, 10);
    let filteredRows = [];
    let totalEntriesCount = 0;
    let totalPages = 0;

    function filterTable() {
        const searchTerm = searchBar.value.toLowerCase().trim();
        const selectedRole = roleFilterDropdown.getAttribute('data-selected-role') || 'all';

        filteredRows = tableRows.filter(row => {
            const cells = Array.from(row.cells);
            const matchesSearch = cells.some(cell => cell.textContent.toLowerCase().includes(searchTerm));
            const roleCell = cells[5]; // Assuming the role is in the 6th column (index 5)
            const matchesRole = selectedRole === 'all' || roleCell.textContent.toLowerCase() === selectedRole;

            return matchesSearch && matchesRole;
        });

        totalEntriesCount = filteredRows.length;
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
        updateRoleCounts(); // Update role counts after filtering
    }

    function updateTable() {
        const startIndex = (currentPage - 1) * entriesPerPage;
        const endIndex = startIndex + entriesPerPage;

        // Hide all rows
        tableRows.forEach(row => row.style.display = 'none');

        // Show only the rows that are part of the current page
        filteredRows.slice(startIndex, endIndex).forEach(row => row.style.display = '');

        visibleEntries.textContent = filteredRows.slice(startIndex, endIndex).length;
        totalEntries.textContent = totalEntriesCount;

        updatePagination();
    }

    function updatePagination() {
        const pageItems = Array.from(pagination.querySelectorAll('.page-item:not(#prev-page):not(#next-page)'));
        pageItems.forEach(item => item.remove());

        prevPageButton.classList.toggle('disabled', currentPage === 1);
        nextPageButton.classList.toggle('disabled', currentPage === totalPages);

        for (let i = 1; i <= totalPages; i++) {
            const pageItem = document.createElement('li');
            pageItem.className = `page-item ${i === currentPage ? 'active' : ''}`;
            pageItem.innerHTML = `<a class="page-link" href="#">${i}</a>`;
            pageItem.addEventListener('click', (event) => {
                event.preventDefault();
                currentPage = i;
                updateTable();
            });
            pagination.insertBefore(pageItem, nextPageButton);
        }
    }

    function getSelectedRowsCount() {
        return formDataTable.querySelectorAll('input[type="checkbox"]:checked:not(#selectAll)').length;
    }

    function updateRecordsInfo() {
        document.getElementById('records-info').textContent = `(Records Found: ${totalEntriesCount}, Selected: ${getSelectedRowsCount()})`;
    }

    function updateRoleCounts() {
        // Reset counts for all roles
        roleFilterItems.forEach(item => {
            const role = item.getAttribute('data-value');
            let roleCount = 0;

            // Count rows that match the role
            tableRows.forEach(row => {
                const cells = Array.from(row.cells);
                const rowRole = cells[5]?.textContent.toLowerCase() || ''; // Assuming role is in the 6th column
                if (role === 'all' || rowRole === role) {
                    roleCount++;
                }
            });

            // Update the count in the dropdown
            item.querySelector('.option-count').textContent = `${roleCount}`;
        });
    }

    selectAllCheckbox.addEventListener('change', function() {
        const checkboxes = formDataTable.querySelectorAll('input[type="checkbox"]:not(#selectAll)');
        checkboxes.forEach(checkbox => checkbox.checked = this.checked);
        updateRecordsInfo();
    });

    formDataTable.addEventListener('change', function(event) {
        if (event.target.type === 'checkbox' && event.target !== selectAllCheckbox) {
            selectAllCheckbox.checked = Array.from(formDataTable.querySelectorAll('input[type="checkbox"]:not(#selectAll)')).every(checkbox => checkbox.checked);
            updateRecordsInfo();
        }
    });

    searchBar.addEventListener('input', function() {
        filterTable();
        updateRecordsInfo();
    });

    roleFilterItems.forEach(item => {
        item.addEventListener('click', function() {
            roleFilterDropdown.setAttribute('data-selected-role', item.getAttribute('data-value'));
            roleFilterDropdown.textContent = item.textContent;
            filterTable();
            updateRecordsInfo();
        });
    });

    entriesPerPageSelect.addEventListener('change', function() {
        entriesPerPage = parseInt(this.value, 10);
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
    });

    prevPageButton.addEventListener('click', function(event) {
        event.preventDefault();
        if (currentPage > 1) {
            currentPage--;
            updateTable();
        }
    });

    nextPageButton.addEventListener('click', function(event) {
        event.preventDefault();
        if (currentPage < totalPages) {
            currentPage++;
            updateTable();
        }
    });

    document.querySelectorAll('.role-filter .dropdown-item').forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const selectedText = this.innerHTML;
            document.getElementById('roleFilterDropdown').innerHTML = selectedText;
        });
    });

    filterTable(); // Initial filter to set up table and counts
    updateRecordsInfo(); // Ensure records info is updated initially
});

document.getElementById('adminUserModal').addEventListener('hidden.bs.modal', function (e) {
    var form = document.getElementById('adminUserForm');
    form.reset(); // Reset form fields
    document.getElementById('selectedDepartments').innerHTML = ''; 
    const inputs = document.querySelectorAll(".form-control, .form-select");
      inputs.forEach(input => input.classList.remove("filled"));
  });


  