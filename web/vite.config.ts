import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// emptyOutDir стирает каталог целиком вместе с .gitkeep, а без хотя бы одного
// файла в webdist не собирается go:embed на чистом клоне. Возвращаем метку
// сразу после сборки, чтобы репозиторий не оказывался «грязным».
const keepEmbedDir = (outDir: string) => ({
  name: "netos-keep-embed-dir",
  closeBundle() {
    const path = fileURLToPath(new URL(`${outDir}/.gitkeep`, import.meta.url));
    writeFileSync(path, "\r\n");
  },
});

// Сборка кладётся прямо в каталог, который встраивается в бинарник netosd.
// Отдельного шага копирования нет намеренно: рассинхронизация между собранным
// интерфейсом и бинарником — источник трудноуловимых ошибок.
export default defineConfig({
  plugins: [react(), keepEmbedDir("../backend/internal/api/webdist")],
  build: {
    outDir: "../backend/internal/api/webdist",
    emptyOutDir: true,
    // Один файл на ассет без хэшей: панель отдаётся с самого роутера,
    // кэш сбрасывается вместе с обновлением бинарника.
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: "app.[ext]",
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "https://45.38.170.119:8443",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
