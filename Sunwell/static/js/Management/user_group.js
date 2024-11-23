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






//form script

// floatimg labels
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
  document.addEventListener("DOMContentLoaded", function() {
    const commGroupSelect = document.getElementById('commGroup');
    const accessibleDepartmentSelect = document.getElementById('accessibleDepartment');
    const selectedDepartmentsDiv = document.getElementById('selectedDepartments');

    // Function to update the visible options based on the selected commGroup
    function filterDepartments() {
        const commGroupValue = commGroupSelect.value;
        const options = accessibleDepartmentSelect.querySelectorAll('option');

        options.forEach(option => {
            if (option.dataset.commgroup === commGroupValue || commGroupValue === "") {
                option.style.display = "block";
            } else {
                option.style.display = "none";
            }
        });

        // Reset the selection if no commGroup is selected
        accessibleDepartmentSelect.disabled = !commGroupValue;
        if (!commGroupValue) {
            accessibleDepartmentSelect.value = ""; // Clear selection
        }
        
        // Update the display of selected departments
        updateSelectedDepartments();
    }

    // Function to update the selected departments display
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

    // Add event listeners
    commGroupSelect.addEventListener('change', filterDepartments);
    accessibleDepartmentSelect.addEventListener('change', updateSelectedDepartments);

    // Initial call to set up the filter and display selected departments
    filterDepartments();
});

//table script
document.addEventListener("DOMContentLoaded", function () {
    const searchBar = document.getElementById('searchBar');
    const deptFilterDropdown = document.getElementById('deptFilterDropdown');
    const deptFilterItems = document.querySelectorAll('.dept-filter .dropdown-item');
    const formDataTable = document.getElementById('form-data-table');
    const tableRows = Array.from(formDataTable.querySelectorAll('tr'));
    const visibleEntries = document.getElementById('visible-entries');
    const totalEntries = document.getElementById('total-entries');
    const recordsInfo = document.getElementById('records-info');
    const entriesPerPageSelect = document.getElementById('entriesPerPage');
    const pagination = document.querySelector('.pagination');
    const selectAllCheckbox = document.getElementById('selectAll');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');

    let currentPage = 1;
    let entriesPerPage = parseInt(entriesPerPageSelect.value, 10);
    let filteredRows = tableRows;
    let totalEntriesCount = 0;
    let totalPages = 0;

    function applyDepartmentFilter() {
        const selectedDepartmentId = localStorage.getItem("selectedDepartmentId");
        filteredRows = tableRows.filter(row => {
            const rowDepartmentId = row.getAttribute("data-department-id");
            const isVisible = !selectedDepartmentId || rowDepartmentId === selectedDepartmentId;
            row.style.display = isVisible ? '' : 'none';
            return isVisible;
        });
        filterTable(); // Apply search filter after department filter
    }

    function filterTable() {
        const searchTerm = searchBar.value.toLowerCase().trim();
        filteredRows = filteredRows.filter(row => {
            const cells = Array.from(row.cells);
            return cells.some(cell => cell.textContent.toLowerCase().includes(searchTerm));
        });
        totalEntriesCount = filteredRows.length;
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
        updateRecordsInfo();
    }

    function updateTable() {
        const startIndex = (currentPage - 1) * entriesPerPage;
        const endIndex = startIndex + entriesPerPage;

        // Hide all rows
        tableRows.forEach(row => row.style.display = 'none');

        // Show only the rows that are part of the current page
        const visibleRows = filteredRows.slice(startIndex, endIndex);
        visibleRows.forEach(row => row.style.display = '');

        // Update counts for visible entries and total entries
        visibleEntries.textContent = visibleRows.length;
        totalEntries.textContent = totalEntriesCount;

        updatePagination();
        updateRecordsInfo();
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
        return filteredRows.filter(row => row.querySelector('input[type="checkbox"]').checked).length;
    }

    function updateRecordsInfo() {
        recordsInfo.textContent = `(Records Found: ${totalEntriesCount}, Selected: ${getSelectedRowsCount()})`;
    }

    selectAllCheckbox.addEventListener('change', function () {
        // Select only checkboxes in the visible filtered rows for the current page
        const visibleCheckboxes = filteredRows.slice((currentPage - 1) * entriesPerPage, currentPage * entriesPerPage);
        visibleCheckboxes.forEach(row => {
            row.querySelector('input[type="checkbox"]').checked = selectAllCheckbox.checked;
        });
        updateRecordsInfo();
    });

    formDataTable.addEventListener('change', function (event) {
        if (event.target.type === 'checkbox' && event.target !== selectAllCheckbox) {
            // Update the master checkbox status based on individual checkbox selections
            const visibleCheckboxes = filteredRows.slice((currentPage - 1) * entriesPerPage, currentPage * entriesPerPage);
            selectAllCheckbox.checked = visibleCheckboxes.every(row => row.querySelector('input[type="checkbox"]').checked);
            updateRecordsInfo();
        }
    });

    searchBar.addEventListener('input', function () {
        applyDepartmentFilter(); // Reapply department filter when search term changes
    });

    deptFilterItems.forEach(item => {
        item.addEventListener('click', function () {
            deptFilterDropdown.setAttribute('data-selected-dept', item.getAttribute('data-value'));
            deptFilterDropdown.textContent = item.textContent;
            localStorage.setItem("selectedDepartmentId", item.getAttribute('data-value'));
            applyDepartmentFilter();
        });
    });

    entriesPerPageSelect.addEventListener('change', function () {
        entriesPerPage = parseInt(this.value, 10);
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
    });

    prevPageButton.addEventListener('click', function (event) {
        event.preventDefault();
        if (currentPage > 1) {
            currentPage--;
            updateTable();
        }
    });

    nextPageButton.addEventListener('click', function (event) {
        event.preventDefault();
        if (currentPage < totalPages) {
            currentPage++;
            updateTable();
        }
    });

    document.getElementById("departmentSelect").addEventListener("change", function () {
        const selectedDepartmentId = this.value;
        localStorage.setItem("selectedDepartmentId", selectedDepartmentId);
        applyDepartmentFilter();
    });

    applyDepartmentFilter(); // Initial filter to set up table and counts
});

// Reset the form and other elements when the modal is hidden
document.getElementById('adminUserModal').addEventListener('hidden.bs.modal', function (e) {
    var form = document.getElementById('adminUserForm');
    form.reset(); // Reset form fields
    document.getElementById('selectedDepartments').innerHTML = ''; 
    const inputs = document.querySelectorAll(".form-control, .form-select");
    inputs.forEach(input => input.classList.remove("filled"));
});




  
