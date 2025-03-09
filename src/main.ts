import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

async function authenticate() {
  await invoke("authenticate" );
}

window.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#authenticate-form")?.addEventListener("submit", (e) => {
    e.preventDefault();
    authenticate();
  });

  listen("token", (event) => {
    let el = document.querySelector("#token-info");
    if (el) {
      el.textContent = "Access token received: " + event.payload as string;
    }
  });
});
