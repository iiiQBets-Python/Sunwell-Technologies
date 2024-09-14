document.addEventListener("DOMContentLoaded", function() {
    // Get the necessary elements
    const commGroupSelect = document.getElementById('commGroup');
    const departmentSelect = document.getElementById('departmentName');
    const accessibleDepartmentSelect = document.getElementById('accessibleDepartment');
    const selectedDepartmentsDiv = document.getElementById('selectedDepartments');

    // Function to filter the "Select Department" dropdown based on selected CommGroup
    function filterDepartments() {
        const commGroupValue = commGroupSelect.value;
        const departmentOptions = departmentSelect.querySelectorAll('option');

        departmentOptions.forEach(option => {
            if (option.dataset.commgroup === commGroupValue || commGroupValue === "") {
                option.style.display = "block";
            } else {
                option.style.display = "none";
            }
        });

        // Enable/disable the department select based on CommGroup selection
        departmentSelect.disabled = !commGroupValue;
        departmentSelect.value = ""; // Reset the department selection
    }

    // Function to update the selected accessible departments display
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

    // Event listeners
    commGroupSelect.addEventListener('change', filterDepartments);
    accessibleDepartmentSelect.addEventListener('change', updateSelectedDepartments);

    // Initial setup
    filterDepartments(); // Filter "Select Department" based on the initially selected CommGroup
    updateSelectedDepartments(); // Display initially selected accessible departments
});


//table script
document.addEventListener("DOMContentLoaded", function() {
    const searchBar = document.getElementById('searchBar');
    const deptFilterDropdown = document.getElementById('deptFilterDropdown');
    const deptFilterItems = document.querySelectorAll('.dept-filter .dropdown-item');
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
        const selectedDept = deptFilterDropdown.getAttribute('data-selected-dept') || 'all';

        filteredRows = tableRows.filter(row => {
            const cells = Array.from(row.cells);
            const matchesSearch = cells.some(cell => cell.textContent.toLowerCase().includes(searchTerm));
            const deptCell = cells[3]; // Assuming the department is in the 4th column (index 3)
            const matchesDept = selectedDept === 'all' || deptCell.textContent.toLowerCase() === selectedDept;

            return matchesSearch && matchesDept;
        });

        totalEntriesCount = filteredRows.length;
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
        updateDeptCounts(); // Update department counts after filtering
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

    function updateDeptCounts() {
        // Reset counts for all departments
        deptFilterItems.forEach(item => {
            const dept = item.getAttribute('data-value');
            let deptCount = 0;

            // Count rows that match the department
            tableRows.forEach(row => {
                const cells = Array.from(row.cells);
                const rowDept = cells[3]?.textContent.toLowerCase() || ''; // Assuming department is in the 4th column
                if (dept === 'all' || rowDept === dept) {
                    deptCount++;
                }
            });

            // Update the count in the dropdown
            item.querySelector('.option-count').textContent = `${deptCount}`;
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

    deptFilterItems.forEach(item => {
        item.addEventListener('click', function() {
            deptFilterDropdown.setAttribute('data-selected-dept', item.getAttribute('data-value'));
            deptFilterDropdown.textContent = item.textContent;
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

    document.querySelectorAll('.dept-filter .dropdown-item').forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const selectedText = this.innerHTML;
            document.getElementById('deptFilterDropdown').innerHTML = selectedText;
        });
    });

    filterTable(); // Initial filter to set up table and counts
    updateRecordsInfo(); // Ensure records info is updated initially
});

// Reset the form and other elements when the modal is hidden
document.getElementById('adminUserModal').addEventListener('hidden.bs.modal', function (e) {
    var form = document.getElementById('adminUserForm');
    form.reset(); // Reset form fields
    document.getElementById('selectedDepartments').innerHTML = ''; 
    const inputs = document.querySelectorAll(".form-control, .form-select");
    inputs.forEach(input => input.classList.remove("filled"));
});



  
