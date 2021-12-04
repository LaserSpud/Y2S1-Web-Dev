(function() {
    const form = document.querySelector('#Setfavpicform');
    const checkboxes = form.querySelectorAll('input[type=checkbox]');
    const checkboxLength = checkboxes.length;
    const firstCheckbox = checkboxLength > 0 ? checkboxes[0] : null;

    function init() {
        if (firstCheckbox) {
            for (let i = 0; i < checkboxLength; i++) {
                checkboxes[i].addEventListener('change', checkValidity);
            }

            checkValidity();
        }
    }

    function isChecked() {
        const checkedCheckboxes = form.querySelectorAll('input[type="checkbox"]:checked');

        return checkedCheckboxes.length >= 2;
    }

    function checkValidity() {
        const errorMessage = !isChecked() ? 'At least two checkboxes must be selected.' : '';
        firstCheckbox.setCustomValidity(errorMessage);
    }

    init();
})();
