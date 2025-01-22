document.addEventListener('DOMContentLoaded', function () {
    const gridViewButton = document.getElementById('gridViewButton');
    const listViewButton = document.getElementById('listViewButton');
    const gridView = document.getElementById('gridView');
    const tableView = document.getElementById('tableView');
    const searchBar = document.getElementById('searchBar');
    const cards = document.querySelectorAll('.card-wrapper');
    const tableRows = document.querySelectorAll('#form-data-table tr');
    const recordsInfo = document.getElementById('records-info');
    const entriesDropdown = document.getElementById('entriesPerPage');
    const visibleEntries = document.getElementById('visible-entries');
    const totalEntries = document.getElementById('total-entries');
    const dropdownButton = document.getElementById('roleFilterDropdown');
    const dropdownItems = document.querySelectorAll('.dropdown-item[data-value]');

    let selectedStatus = 'all'; // Default status filter
    let selectedEntries = parseInt(entriesDropdown.value); // Default entries per page

    function updateEntries() {
        const searchTerm = searchBar.value.toLowerCase();
        const totalDataCount = Math.max(cards.length, tableRows.length); // Total number of data items
        let gridVisibleCount = 0;
        let tableVisibleCount = 0;

        totalEntries.textContent = totalDataCount; // Update total entries

        // Filter grid view cards
        cards.forEach((card, index) => {
            const cardTitle = card.querySelector('.card-title').textContent.toLowerCase();
            const cardStatus = card.getAttribute('data-status');

            if (
                (selectedStatus === 'all' || cardStatus === selectedStatus) &&
                cardTitle.includes(searchTerm)
            ) {
                if (index < selectedEntries || selectedEntries === 'all') {
                    card.style.display = 'block';
                    gridVisibleCount++;
                } else {
                    card.style.display = 'none';
                }
            } else {
                card.style.display = 'none';
            }
        });

        // Filter table view rows
        tableRows.forEach((row, index) => {
            const rowText = row.textContent.toLowerCase();
            const rowStatus = row.cells[1].textContent.trim().toLowerCase();

            if (
                (selectedStatus === 'all' || rowStatus === selectedStatus) &&
                rowText.includes(searchTerm)
            ) {
                if (index < selectedEntries || selectedEntries === 'all') {
                    row.style.display = '';
                    tableVisibleCount++;
                } else {
                    row.style.display = 'none';
                }
            } else {
                row.style.display = 'none';
            }
        });

        const visibleCount = Math.max(gridVisibleCount, tableVisibleCount);
        visibleEntries.textContent = visibleCount; // Update visible entries
        recordsInfo.textContent = `(Records Found: ${visibleCount})`; // Update records info
    }

    function filterByStatus(status) {
        selectedStatus = status; // Update the selected status

        // Update the dropdown button text
        if (status === 'all') {
            dropdownButton.innerHTML = `All Status`;
        } else if (status === 'online') {
            dropdownButton.innerHTML = `<i class="fa-regular fa-circle-check" style="color: #28a745;"></i> Online`;
        } else if (status === 'offline') {
            dropdownButton.innerHTML = `<i class="fa-regular fa-circle-stop" style="color: #d20f0f;"></i> Offline`;
        }

        updateEntries(); // Reapply the filter with the updated status
    }

    function switchToGridView() {
        gridView.style.display = 'flex';
        tableView.style.display = 'none';
        updateEntries(); // Reapply filters
    }

    function switchToListView() {
        gridView.style.display = 'none';
        tableView.style.display = 'block';
        updateEntries(); // Reapply filters
    }

    // Event listeners
    gridViewButton.addEventListener('click', switchToGridView);
    listViewButton.addEventListener('click', switchToListView);

    dropdownItems.forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const status = this.getAttribute('data-value');
            filterByStatus(status);
        });
    });

    entriesDropdown.addEventListener('change', function () {
        selectedEntries = this.value === 'all' ? 'all' : parseInt(this.value);
        updateEntries();
    });

    searchBar.addEventListener('input', updateEntries);

    // Initialize with all status
    filterByStatus('all');
});


















