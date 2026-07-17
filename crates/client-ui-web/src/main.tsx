import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
// Self-hosted fonts (offline-safe). The packages register 'Inter Variable' /
// 'JetBrains Mono Variable'; fonts.css aliases the plain family names that
// tokens.css references.
import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';
import './styles/fonts.css';
import './styles/tokens.css';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root element not found');

createRoot(rootEl).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
