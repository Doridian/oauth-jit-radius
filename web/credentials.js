async function waitFrame() {
    return new Promise(resolve => {
        requestAnimationFrame(resolve);
    });
}

async function copyInt(element) {
    try {
        const value = element.querySelector('.copyvalue').dataset.value;
        if (!value) {
            throw new Error('No value to copy');
        }

        await navigator.clipboard.writeText(value);
        await waitFrame();
        element.classList.remove('copydone');
        await waitFrame();
        element.classList.add('copydone');
    } catch (err) {
        console.error('Failed to copy', err);
        alert(`Failed to copy: ${err.text || err}`);
    }
}

function addElementInt(element) {
    element.addEventListener('click', e => {
        copyInt(element);
    });
}

function init() {
    document.querySelectorAll('.copyable').forEach(addElementInt);
}
