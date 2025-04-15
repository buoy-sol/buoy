import { createContext, useContext, useReducer, useState } from "react"
import { useConnect, useDisconnect, useWallets } from "@wallet-standard/react-core"

const WalletContext = createContext(null, null)

function WalletProvider({ children }) {
    let [impl, _] = useWallets()

    if (!impl) {
	let current, setter = null
	console.log("no wallet detected")
	return <>{children}</>
    }

    let [isConnecting, connect] = useConnect(impl)
    let [isDisconnecting, disconnect] = useDisconnect(impl)
    
    let [wallet, setWallet] = useReducer(function(old, e) {
	if (isDisconnecting) {
	    return disconnect()
	}
	
	return connect()
    }, impl)

    return <WalletContext.Provider value={{wallet, setWallet}}>
	{children}
    </WalletContext.Provider>
}

export { WalletContext, WalletProvider }
