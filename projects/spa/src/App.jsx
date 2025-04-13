import { useState } from 'react'
import AppRouter from './components/Router.jsx'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
      <>
        <AppRouter />
      </>
  )
}

export default App
