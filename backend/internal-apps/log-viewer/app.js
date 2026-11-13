// The filter boxes. The server builds each list; CSS opens it while its box has
// focus. This only narrows a list as you type, and makes Enter pick the first value still
// shown (or, with none shown, what you typed). It never touches log text.
for (const box of document.querySelectorAll(".pick input")) {
  const buttons = [...box.closest(".pick").querySelectorAll("li button")];
  box.addEventListener("input", () => {
    const t = box.value.trim().toLowerCase();
    for (const b of buttons) b.parentElement.hidden = !b.value.toLowerCase().includes(t);
  });
  box.addEventListener("keydown", (e) => {
    const first = buttons.find((b) => !b.parentElement.hidden);
    if (e.key === "Enter" && box.value.trim() && first) {
      e.preventDefault();
      box.value = "";
      first.click();
    }
  });
  for (const b of buttons) b.addEventListener("click", () => { box.value = ""; });
}
