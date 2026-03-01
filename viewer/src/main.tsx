import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ThemeProvider } from './context/theme-context'
import { SchemaProvider } from './context/schema-context'
import { LiveProvider } from './context/live-context'
import { App } from './app'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <LiveProvider>
        <SchemaProvider>
          <App />
        </SchemaProvider>
      </LiveProvider>
    </ThemeProvider>
  </StrictMode>,
)
