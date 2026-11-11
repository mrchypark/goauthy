// Apply the library-rendered native component contract without replacing live controls.
(() => {
  const root = document.getElementById('app');
  const prototypes = document.getElementById('elysdui-prototypes')?.content;
  if (!root || !prototypes || typeof MutationObserver === 'undefined') return;
  const selectors = {
    button: 'button, a.button',
    input: 'input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=file]):not([type=color]):not([type=range]):not([type=submit]):not([type=button]):not([type=reset])',
    textarea: 'textarea',
    select: 'select',
    table: 'table'
  };
  const samples = Object.fromEntries(Object.keys(selectors).map(name => [name, prototypes.querySelector(name)]));
  function apply(node) {
    if (node.nodeType !== 1) return;
    for (const [name, selector] of Object.entries(selectors)) {
      const sample = samples[name];
      if (!sample) continue;
      const elements = [...(node.matches(selector) ? [node] : []), ...node.querySelectorAll(selector)];
      for (const element of elements) {
        if (name === 'button' && element.closest('.theme-mode')) continue;
        if (element.dataset.elysdui === 'true') continue;
        element.dataset.elysdui = 'true';
        for (const className of sample.classList) element.classList.add(className);
        if (name === 'table') {
          if (element.parentElement) {
            element.parentElement.classList.add('ui-table-wrap');
            element.parentElement.tabIndex = 0;
          }
          continue;
        }
        element.dataset.slot = name;
        if (name === 'button') {
          element.dataset.variant = element.classList.contains('secondary') ? 'secondary' : 'primary';
          element.dataset.size = 'default';
        }
      }
    }
  }
  apply(root);
  new MutationObserver(records => {
    for (const record of records) for (const node of record.addedNodes) apply(node);
  }).observe(root, {childList: true, subtree: true});
})();
