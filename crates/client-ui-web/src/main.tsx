import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import './styles/tokens.css';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root element not found');

createRoot(rootEl).render(<App />);
