import AppRouter from './components/Router.jsx'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

import { WalletProvider } from "./contexts/WalletContext"

function App() {
    return (
	<WalletProvider>
            <AppRouter />
	</WalletProvider>
    )
}

export default App
