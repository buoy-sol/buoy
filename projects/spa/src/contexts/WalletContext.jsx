import bs58 from "bs58"

import { getUiWalletAccountStorageKey, uiWalletAccountBelongsToUiWallet, uiWalletAccountsAreSame, useWallets } from "@wallet-standard/react"
import { createContext, useContext, useEffect, useMemo, useReducer, useState } from "react"

import { SolanaSignMessage } from "@solana/wallet-standard-features"
import { getWalletAccountFeature } from "@wallet-standard/ui"
import { getWalletAccountForUiWalletAccount_DO_NOT_USE_OR_YOU_WILL_BE_FIRED } from "@wallet-standard/ui-registry"

import { API } from "../utils/api"

const WalletContext = createContext(null, null)
const ACCOUNT_ALIAS = "solana:chosen-wallet-and-address";
const ACCOUNT_AUTHN_STATUS = "solana:authenticated-account"

let hasAccount = false;

/**
 *
 */
async function authenticate(walletAccount) {
    let messageSigner = getWalletAccountFeature(walletAccount, SolanaSignMessage)
    let nonce = bs58.encode(crypto.getRandomValues(new Uint8Array(Array.from({ length: 12 }))))
    let challengeResponse = await fetch(
	`${API}/authn/challenge`,
	{
	    method: "POST",
	    body: JSON.stringify({
		address: walletAccount.address,
		nonce: nonce
	    }),
	    headers: {"content-type": "application/json"}
	}
    )
    let challenge = await challengeResponse.json()

    let account = getWalletAccountForUiWalletAccount_DO_NOT_USE_OR_YOU_WILL_BE_FIRED(walletAccount)
    let input = {message: challenge.message}

    let inputsWithAccount = [{message: bs58.decode(challenge.message)}].map(function(e){ return {...e, account} })
    let results = await messageSigner.signMessage(...inputsWithAccount)
    let { signature, signedMessage } = results[0]
    
    if (!signature) {
	throw new Error("??")
    }
    
    let handled = await fetch(
	`${API}/authn/verify`,
	{
	    method: "POST",
	    body: JSON.stringify({
		address: walletAccount.address,
		nonce: nonce,
		signature: bs58.encode(signature)
	    }),
	    headers: {
		"Content-type": "application/json"
	    }
	}
    )

    if (! handled.ok) {
	throw new Error(`Failed!`)
    }

    let {handle} = await handled.json()
    let resolution = await fetch(`${API}/authn?handle=${handle}`)
    let resolved = await resolution.json()

    localStorage.setItem("bearer", resolved.bearer)
    window.location.replace(resolved.location)
}


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

	// if (walletAccount) {
	//    authenticate(walletAccount)
	// }
    }, [selected, walletAccount])
    
    return <WalletContext.Provider value={useMemo(function() { return [walletAccount, setSelected, [walletAccount]]})}>
	{children}
    </WalletContext.Provider>
}

export { WalletContext, WalletProvider, authenticate }
