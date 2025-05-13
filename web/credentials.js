async function waitFrame() {
    return new Promise(resolve => {
        requestAnimationFrame(resolve);
    });
}

async function copyInt(element, text) {
    await navigator.clipboard.writeText(text);
    await waitFrame();
    element.classList.remove('copydone');
    await waitFrame();
    element.classList.add('copydone');
}

function addElementInt(element) {
    element.addEventListener('click', e => {
        e.preventDefault();
        e.stopPropagation();
        const value = element.querySelector('.copyvalue');
        copyInt(element, value.innerText).catch(err => {
            alert('Failed to copy: ', err);
        });
    });
}

function init() {
    document.querySelectorAll('.copyable').forEach(addElementInt);
}
