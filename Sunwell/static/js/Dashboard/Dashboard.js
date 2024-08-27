document.addEventListener('DOMContentLoaded', function() {
    const gridViewButton = document.getElementById('gridViewButton');
    const listViewButton = document.getElementById('listViewButton');
    const gridView = document.getElementById('gridView');
    const tableView = document.getElementById('tableView');
    const searchBar = document.getElementById('searchBar');
    const cards = document.querySelectorAll('.card-wrapper');
    const tableBody = document.getElementById('form-data-table');
    const entriesPerPageSelect = document.getElementById('entriesPerPage');
    const recordsInfo = document.getElementById('records-info');
    const visibleEntriesSpan = document.getElementById('visible-entries');
    const totalEntriesSpan = document.getElementById('total-entries');
    const dropdownItems = document.querySelectorAll('.dropdown-item[data-value]');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');
    let entriesPerPage = parseInt(entriesPerPageSelect.value);
    let currentPage = 1;

    function updateGridPagination() {
        const visibleCards = Array.from(cards).filter(card => card.style.display !== 'none');
        const totalEntriesCount = visibleCards.length;
        const start = (currentPage - 1) * entriesPerPage;
        const end = start + entriesPerPage;

        visibleCards.forEach((card, index) => {
            card.style.display = (index >= start && index < end) ? 'block' : 'none';
        });

        updatePaginationControls(totalEntriesCount);
        updateRecordCount(visibleCards.length);
    }

    function updateTablePagination() {
        const filteredData = Array.from(tableBody.getElementsByTagName('tr')).filter(row => row.style.display !== 'none');
        const totalEntriesCount = filteredData.length;
        const start = (currentPage - 1) * entriesPerPage;
        const end = start + entriesPerPage;

        filteredData.forEach((row, index) => {
            row.style.display = (index >= start && index < end) ? '' : 'none';
        });

        updatePaginationControls(totalEntriesCount);
        updateRecordCount(filteredData.length);
    }

    function updatePaginationControls(totalEntriesCount) {
        prevPageButton.classList.toggle('disabled', currentPage === 1);
        nextPageButton.classList.toggle('disabled', currentPage * entriesPerPage >= totalEntriesCount);

        const startEntry = (currentPage - 1) * entriesPerPage + 1;
        const endEntry = Math.min(currentPage * entriesPerPage, totalEntriesCount);
        visibleEntriesSpan.textContent = `${startEntry} to ${endEntry}`;
        totalEntriesSpan.textContent = totalEntriesCount;
    }

    function updateRecordCount(visibleCount) {
        recordsInfo.textContent = `Records Found: ${visibleCount}`;
    }

    function updateDropdownCounts() {
        let onlineCount = 0;
        let offlineCount = 0;

        cards.forEach(card => {
            const status = card.getAttribute('data-status');
            if (status === 'online') {
                onlineCount++;
            } else if (status === 'offline') {
                offlineCount++;
            }
        });

        document.querySelector('.dropdown-menu [data-value="online"] .option-count').textContent = onlineCount;
        document.querySelector('.dropdown-menu [data-value="offline"] .option-count').textContent = offlineCount;
        document.querySelector('.dropdown-menu [data-value="all"] .option-count').textContent = onlineCount + offlineCount;
    }

    function updateCardVisibility() {
        const searchTerm = searchBar.value.toLowerCase();
        const selectedValue = document.querySelector('.dropdown-item.active')?.getAttribute('data-value') || 'all';
        let visibleCount = 0;

        cards.forEach(card => {
            const titleElement = card.querySelector('.card-title');
            const bodyText = card.querySelector('.card-body').textContent.toLowerCase();
            const status = card.getAttribute('data-status');
            const titleText = titleElement ? titleElement.textContent.toLowerCase() : '';
            const matchesSearch = titleText.includes(searchTerm) || bodyText.includes(searchTerm);
            const matchesStatus = selectedValue === 'all' || status === selectedValue;

            if (matchesSearch && matchesStatus) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        updateGridPagination();
        updateRecordCount(visibleCount);
    }

    function updateTableVisibility() {
        const searchTerm = searchBar.value.toLowerCase();
        const selectedValue = document.querySelector('.dropdown-item.active')?.getAttribute('data-value') || 'all';
        let visibleCount = 0;

        Array.from(tableBody.getElementsByTagName('tr')).forEach(row => {
            const rowText = row.textContent.toLowerCase();
            const statusText = row.cells[1].textContent.trim().toLowerCase();
            const matchesSearch = rowText.includes(searchTerm);
            const matchesStatus = selectedValue === 'all' || statusText.includes(selectedValue);

            if (matchesSearch && matchesStatus) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        updateTablePagination();
        updateRecordCount(visibleCount);
    }

    function switchToGridView() {
        gridView.style.display = 'flex';
        tableView.style.display = 'none';
        updateCardVisibility();
    }

    function switchToListView() {
        gridView.style.display = 'none';
        tableView.style.display = 'block';
        updateTableVisibility();
    }

    gridViewButton.addEventListener('click', switchToGridView);
    listViewButton.addEventListener('click', switchToListView);

    searchBar.addEventListener('input', function() {
        updateCardVisibility();
        updateTableVisibility();
    });

    dropdownItems.forEach(item => {
        item.addEventListener('click', function() {
            dropdownItems.forEach(i => i.classList.remove('active'));
            this.classList.add('active');
            updateCardVisibility();
            updateTableVisibility();
        });
    });

    entriesPerPageSelect.addEventListener('change', function() {
        entriesPerPage = parseInt(this.value);
        currentPage = 1;
        updateCardVisibility();
        updateTableVisibility();
    });

    prevPageButton.addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            updateCardVisibility();
            updateTableVisibility();
        }
    });

    nextPageButton.addEventListener('click', function() {
        const totalEntriesCount = gridView.style.display === 'flex' 
            ? Array.from(cards).filter(card => card.style.display !== 'none').length 
            : Array.from(tableBody.getElementsByTagName('tr')).filter(row => row.style.display !== 'none').length;

        if (currentPage * entriesPerPage < totalEntriesCount) {
            currentPage++;
            updateCardVisibility();
            updateTableVisibility();
        }
    });

    document.querySelectorAll('.role-filter .dropdown-item').forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const selectedText = this.innerHTML;
            document.getElementById('roleFilterDropdown').innerHTML = selectedText;
        });
    });

    updateCardVisibility();
    updateTableVisibility();
    updateDropdownCounts();
});











