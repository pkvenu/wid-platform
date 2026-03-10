import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import { ThemeProvider } from './context/ThemeContext.jsx'
import { AuthProvider } from './context/AuthContext.jsx'
import { OnboardingProvider } from './context/OnboardingContext.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider>
      <AuthProvider>
        <OnboardingProvider>
          <App />
        </OnboardingProvider>
      </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>,
)