import {getUiWalletAccountStorageKey, uiWalletAccountBelongsToUiWallet, uiWalletAccountsAreSame, useWallets} from "@wallet-standard/react"
import { createContext, useContext, useEffect, useMemo, useReducer, useState } from "react"


const WalletContext = createContext(null, null)
const ACCOUNT_ALIAS = 'solana:chosen-wallet-and-address';

let hasAccount = false;

/**
 *
 */
function retrieve(wallets) {
    if (hasAccount) {
	return
    }
    
    const retrieved = localStorage.getItem(ACCOUNT_ALIAS)
    if (!retrieved || typeof retrieved !== "string") {
	return
    }

    const [retrievedName, retrievedAddress] = retrieved
    if (!retrievedName || !retrievedAddress) {
	return
    }

    for (const wallet of wallets) {
	if (wallet.name === retrievedName) {
	    for (const account of wallet.accounts) {
		if (account.address === retrievedAddress) {
		    return account
		}
	    }
	}
    }
}

/**
 *
 */
function WalletProvider({ children }) {
    let wallets = useWallets()
    
    let [selected, setSelectedLocal] = useState(function() {
	return retrieve(wallets)
    })

    /**
     *
     */
    function setSelected(setter) {
	setSelectedLocal(
	    function(prevSelected) { // useReducer, essentially
		hasAccount = true
		
		let nextSelected = setter
		if (typeof setter === 'function') {
		    nextSelected = setter(prevSelected)
		}

		let accountKey = undefined
		if (nextSelected) {
		    accountKey = getUiWalletAccountStorageKey(nextSelected)
		}

		localStorage.removeItem(ACCOUNT_ALIAS)
		if (accountKey) {
		    localStorage.setItem(ACCOUNT_ALIAS, accountKey)
		}
		
		return nextSelected
	    }
	)
    }

    let walletAccount = useMemo(function() {
	if (!selected) {
	    return
	}
	
	for (let uiWallet of wallets) {
	    for (let uiWalletAccount of uiWallet.accounts) {
		if (uiWalletAccountsAreSame(selected, uiWalletAccount)) {
		    return uiWalletAccount
		}
	    }
	    if (uiWalletAccountBelongsToUiWallet(selected, uiWallet) && uiWallet.accounts[0]) {
		return uiWallet.accounts[0]
	    }
	}
	
    }, [selected, wallets])
    
    useEffect(function() {
	let retrievedAccount = retrieve(wallets)
	if (retrievedAccount) {
	    setSelectedLocal(retrievedAccount)
	}
    }, [wallets])

    useEffect(function() {
	if (selected && !walletAccount) {
	    setSelectedLocal(undefined)
	}
    }, [selected, walletAccount])
    
    return <WalletContext.Provider value={useMemo(function() { return [walletAccount, setSelected, [walletAccount]]})}>
	{children}
    </WalletContext.Provider>
}

export { WalletContext, WalletProvider }
