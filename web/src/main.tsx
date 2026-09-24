import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
// Шрифты лежат в сборке, а не на Google Fonts: панель открывают и на роутере
// без выхода в интернет. Подключены только латиница и кириллица.
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/cyrillic-400.css";
import "@fontsource/ibm-plex-sans/cyrillic-500.css";
import "@fontsource/ibm-plex-sans/cyrillic-600.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/cyrillic-400.css";
import "@fontsource/jetbrains-mono/cyrillic-500.css";
import "@fontsource/tektur/latin-400.css";
import "@fontsource/tektur/latin-500.css";
import "@fontsource/tektur/cyrillic-400.css";
import "@fontsource/tektur/cyrillic-500.css";
import "./styles.css";

// Применяем сохранённую тему до первого render, чтобы при открытии тёмной
// панели не было короткой белой вспышки.
const savedTheme = localStorage.getItem("netos-theme");
if (savedTheme === "dark" || savedTheme === "light") {
  document.documentElement.setAttribute("data-theme", savedTheme);
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
