document.addEventListener("DOMContentLoaded", function() {
    const searchBar = document.getElementById('searchBar');
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
        
        filteredRows = tableRows.filter(row => {
            const cells = Array.from(row.cells);
            return cells.some(cell => cell.textContent.toLowerCase().includes(searchTerm));
        });

        totalEntriesCount = filteredRows.length;
        totalPages = Math.ceil(totalEntriesCount / entriesPerPage);
        currentPage = 1;
        updateTable();
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

    filterTable(); // Initial filter to set up table and counts
    updateRecordsInfo(); // Ensure records info is updated initially
});


