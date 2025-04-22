import AppRouter from './components/Router.jsx'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

import { AuthProvider } from "./contexts/AuthContext"
import { WalletProvider } from "./contexts/WalletContext"

function App() {
    return (
	<WalletProvider>
	    <AuthProvider>
		<AppRouter />
	    </AuthProvider>
	</WalletProvider>
    )
}

export default App
