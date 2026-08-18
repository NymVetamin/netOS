import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Сборка кладётся прямо в каталог, который встраивается в бинарник netosd.
// Отдельного шага копирования нет намеренно: рассинхронизация между собранным
// интерфейсом и бинарником — источник трудноуловимых ошибок.
export default defineConfig({
  plugins: [react()],
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
