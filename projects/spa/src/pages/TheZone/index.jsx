import bs58 from "bs58"
import { createContext, useContext, useEffect, useRef, useState } from "react"
import { AuthContext } from "../../contexts/AuthContext"
import { WalletContext } from "../../contexts/WalletContext"
import Cardteaser from "../../components/Cardteaser"
import Canvas from "../../components/Canvas"
import Viewer from "../../components/Viewer"
import { API } from "../../utils/api"
import style from "../../utils/style"
import { Navigate } from "react-router-dom"

import {
    address,
    appendTransactionMessageInstruction,
    createSolanaRpc,
    createTransactionMessage,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signAndSendTransactionMessageWithSigners,
} from "@solana/kit"

import { useSignTransaction, useSignAndSendTransaction, useWalletAccountTransactionSendingSigner } from "@solana/react"
import { getTransferSolInstruction } from "@solana-program/system"
// import { signTransaction } from "@solana/transactions"

import { useWallets, useConnect, useDisconnect } from "@wallet-standard/react-core"

const VisibleContext = createContext({
    B: true,
    A: true,
    MENU: false
})

function Menu() {
    let {visible, setVisible} = useContext(VisibleContext)

    function toggle(target) {
	setVisible({...visible, [target]: !visible[target]})
    }
    
    return (
	<div id="menu"
	     style={{display: "flex",
		     alignItems: "center",
		     justifyContent: "center",
		     position: "fixed",
		     top: 0,
		     left: 0,
		     height: "100%",
		     background: style.color.menus}}>
	    <nav>
		<ul style={{padding: 0}}>
		    <li style={{listStyleType: "none", padding: "7px"}}>
			<button className="button" onClick={function() {toggle("MENU")}}>THE ZONE</button>
		    </li>
		    {[
			{href: "/#tokens", text: "YOUR TOKENS"},
			{href: "/#help", text: "HELP & FAQ"},
			{href: "/#settings", text: "SETINGS"}
		    ].map(function(e){
			return (
			    <li key={e} style={{listStyleType: "none"}}>
				<button className="button"><a href={e.href}>{e.text}</a></button>
			    </li>
			)
		    })}
		</ul>
	    </nav>
	</div>
    )
}

function Cardpicker(props) {
    let { style, value: data } = props

    let transactionSendingSigner;
    let signAndSendTransaction;
    
    if (! data) {
        return <p>No card</p>
    }
                                                                                                                                     
    let [selected, setSelected] = useContext(WalletContext)
    let wallets = useWallets()
    let chosen = wallets[0] // @todo user has to make this choice
                                                                       
    // @todo move
    let [isConnecting, connect] = useConnect(chosen)
    let [isDisconnecting, disconnect] = useDisconnect(chosen)
                                                                       
    async function choose(uiwallet) {
        let connected = await connect()
        setSelected(connected[0]) // @todo user has to make this choice

	transactionSendingSigner = useWalletAccountTransactionSendingSigner(chosen.accounts[0], "solana:devnet")
	signAndSendTransaction = useSignAndSendTransaction(chosen.accounts[0], "solana:devnet")
    }
    
    async function signAndSend(txBase64) {
	await choose(null)
        let txBytes = Uint8Array.from(atob(txBase64), function(c) {
            return c.charCodeAt(0)
        })

        return await signAndSendTransaction({transaction: txBytes})
    }
    
    async function pick(cardIdentifier, accessType) {
        let txSignature = null
        if ("rent" == accessType) {
            let rentForCardResp = await fetch(`${API}/cards/${cardIdentifier}/rent`, {credentials: "include"})
            let rentForCard = await rentForCardResp.json()

	    // funds the transfer
	    let txSignatureRaw = await signAndSend(rentForCard.txn_rent_fee)
            txSignature = bs58.encode(txSignatureRaw.signature)
        }
                                                                                                                                     
        await fetch(
            `${API}/cards/pick`,
            {
		credentials: "include",
                method: "POST",
                body: JSON.stringify({card: cardIdentifier, sig: txSignature}),
                headers: {"Content-type": "application/json"}
            }
        )
    }

    let explorer = `https://explorer.solana.com/address/${data.address}?cluster=devnet`
    return (
	<div>
	    <Cardteaser value={props.value} />
	    <button className="button">
		<a target="_blank" href={explorer}>see on chain &#x2197;</a>
	    </button>
	    <button disabled={(data.spl.data.amount == 0)}
		    className="button"
		    style={{background: ((data.spl.data.amount == 0) ? "lightgrey" : "#fff")}}
		    onClick={function(e) {
			pick(data.identifier, data.access)
		    }}>{data.access.toUpperCase()}</button>
	    <p>-</p>
	</div>
    )
	    
}

async function transfer(sender, recipient, lamports) {
    let rpc = createSolanaRpc("https://api.devnet.solana.com")
    try {
	let ix = getTransferSolInstruction({
	    amount: lamports,
	    source: sender,
	    destination: recipient,
	})
	
	let {value: latestBlockhash} = await rpc.getLatestBlockhash({commitment: "confirmed"}).send()
	let msg = pipe(
	    createTransactionMessage({ version: 0 }),
	    function (tx) { return setTransactionMessageFeePayerSigner(sender, tx) },
	    function (tx) { return setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx) },
	    function (tx) { return appendTransactionMessageInstruction(ix, tx) }
	)
	
	return await signAndSendTransactionMessageWithSigners(msg)
    } catch (ex) {
	console.log(`Failed to rent unit! - ${ex}`)
    }
}

export default function TheZone() {

    let session = useContext(AuthContext)
    let viewerRef = useRef(null)
    let [loading, setLoading] = useState(true)
    let [cards, setCards] = useState({})
    let [visible, setVisible] = useState({
	B: true,
	A: true,
	MENU: false,
	RATE: false
    })
    
    function toggle(target) {
	setVisible({...visible, [target]: !visible[target]})
    }

    async function fetchCards() {
	let resp = await fetch(`${API}/cards/choices`, {credentials: "include"})
	setCards(await resp.json())
    }

    useEffect(function () {
	if (session) {
	    setLoading(false)
	}
    }, [session])

    useEffect(function () {
	if (! cards.picked) {
	    fetchCards()
	}
    }, [])
    
    if (loading) {
	return <div>Loading...</div>
    }
    
    if (! session) {
        return <Navigate to={{ pathname: "/" }} />
    }

    if (! cards.picked) {
	return (
	    <VisibleContext.Provider value={{visible, setVisible}}>
		{visible.MENU &&
		 <Menu />}
		<p>Studycard picker!</p>
		<button className="button" onClick={function(){toggle("MENU")}}>MENU</button>
		<div style={{display: "flex"}}>
		    {Object.entries(cards)
		     .filter(function([k, v]) {
			 return ["rent", "free"].includes(k)
		     })
		     .map(function([k, v]) {
			 return <div style={{margin: "1em"}}>
				    <Cardpicker key={k} value={v} />
				</div>
		     })}
		</div>
	    </VisibleContext.Provider>
	)
    }

    return (
	<div id="the-zone" style={{textTransform: "uppercase"}}>
	    <VisibleContext.Provider value={{visible, setVisible}}>
		{visible.MENU &&
		 <Menu />}
		<h2>Welcome to The Zone!</h2>
		<p>THIS HERE IS THE CENTRAL POINT OF THE ENTIRE APPLICATION. NO MATTER WHAT YOU DO YOU ENTER THE ZONE AND EVERYTHING SHOULD BE READY FOR YOU</p>
		
		<div id="the-zone-controls" style={{display: "flex", justifyContent: "center", alignItems: "center"}}>
		    <button className="button" style={{background: style.color.mentor}} onClick={function(){toggle("B")}}>TOGGLE SIDE B</button>
		    <button className="button" style={{background: style.color.student}} onClick={function(){toggle("A")}}>TOGGLE SIDE A</button>
		    <button className="button" onClick={function(){toggle("MENU")}}>MENU</button>
		    <button className="button" onClick={function(){toggle("RATE")}}>DONE</button>
		</div>
		
		<div style={{display: "flex", flexWrap: "wrap"}}>
		    {(!visible.RATE) && visible.B &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Viewer id="focusedB" dashes={style.color.mentor} card={cards.picked} width="500" height="500" />
		     </section>}
		    
		    {(!visible.RATE) && visible.A &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Canvas id="focusedA" dashes={style.color.student} width="500" height="500" />
		     </section>}

		</div>

		{visible.RATE &&
		 <>
		     <p>-</p>
		     <p>GRADE CARD SUCCESS FOR (SM-2 ALGORITHM):</p>
		     
		     <div style={{display: "flex", justifyContent: "center"}}>
			 <button className="button">AGAIN</button>
			 <button className="button">HARD</button>
			 <button className="button">GOOD</button>
			 <button className="button">EASY</button>
		     </div>

		     <p>-</p>
		     <p>RATE CARD DIFFICULTY</p>

		     <div style={{display: "flex", flexDirection: "column", alignItems: "center"}}>
			 {[...Array(10).keys()].map(function(e) {
			     return <button className="button">{e+1}</button>
			 })}
		     </div>
		 </>}
	    </VisibleContext.Provider>
	</div>
    )
}
