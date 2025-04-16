import { createContext, useContext, useEffect, useReducer, useState } from "react"
import { useConnect, useDisconnect, useWallets } from "@wallet-standard/react-core"

const WalletContext = createContext(null, null)

function WalletProvider({ children }) {
    let [impl, _] = useWallets()
    let [wallet, setWallet] = useState([impl])
    let [trigger, setTrigger] = useState(0)

    if (!impl) {
	console.log("NO WALLET DETECTED")
	return <WalletContext.Provider value={null, null}>{children}</WalletContext.Provider>
    }

    let [isConnecting, connect] = useConnect(impl)
    let [isDisconnecting, disconnect] = useDisconnect(impl)

    const connector = async () => {
	if (!wallet.address && trigger > 0) {
	    setWallet(await connect())
	}
    }
    
    useEffect(function() {
	console.log(connector())
    }, [trigger])

    return <WalletContext.Provider value={{wallet, setTrigger}}>
	{children}
    </WalletContext.Provider>
}

export { WalletContext, WalletProvider }
