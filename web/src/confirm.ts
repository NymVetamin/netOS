// HTML dialog удерживает фокус внутри окна и блокирует взаимодействие с фоном.
export function confirmAction(message: string, action = "Подтвердить"): Promise<boolean> {
  // Повторный вызов не должен создавать второе подтверждение поверх первого.
  if (document.querySelector("dialog.action-confirm")) return Promise.resolve(false);
  return new Promise((resolve) => {
    const previous = document.activeElement;
    const dialog = document.createElement("dialog");
    dialog.className = "action-confirm";
    dialog.setAttribute("aria-labelledby", "action-confirm-title");
    dialog.setAttribute("aria-describedby", "action-confirm-description");
    const title = document.createElement("h2");
    title.id = "action-confirm-title";
    title.textContent = action + "?";
    const description = document.createElement("p");
    description.id = "action-confirm-description";
    description.textContent = message;
    const buttons = document.createElement("div");
    buttons.className = "action-confirm-buttons";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn";
    cancel.textContent = "Отмена";
    const accept = document.createElement("button");
    accept.type = "button";
    accept.className = "btn danger";
    accept.textContent = action;
    let done = false;
    const finish = (value: boolean) => {
      if (done) return;
      done = true;
      window.removeEventListener("hashchange", onNavigate);
      dialog.close();
      dialog.remove();
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
      resolve(value);
    };
    const onNavigate = () => finish(false);
    cancel.onclick = () => finish(false);
    accept.onclick = () => finish(true);
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); finish(false); });
    dialog.addEventListener("close", () => finish(false));
    window.addEventListener("hashchange", onNavigate);
    buttons.append(cancel, accept);
    dialog.append(title, description, buttons);
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}
