import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        // Required for SSE — disable response buffering so events stream through live
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            // Tell the proxy not to buffer the response
            proxyRes.headers['x-accel-buffering'] = 'no'
          })
        },
      },
    },
  },
})
