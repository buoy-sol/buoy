import bs58 from "bs58"
import { createContext, useContext, useEffect, useRef, useState } from "react"
import { AuthContext } from "../../contexts/AuthContext"
import { WalletContext } from "../../contexts/WalletContext"
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

import {
    useWalletAccountTransactionSendingSigner
} from "@solana/react"

import { getTransferSolInstruction } from "@solana-program/system"

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
			"YOUR SALES",
			"HELP & FAQ",
			"SETINGS"
		    ].map(function(e){
			return (
			    <li key={e} style={{listStyleType: "none"}}>
				<button className="button">{e}</button>
			    </li>
			)
		    })}
		</ul>
	    </nav>
	</div>
    )
}

async function transfer(sender, recipient, lamports) {
    let rpc = createSolanaRpc("https://api.devnet.solana.com")
    try {
	let ix = getTransferSolInstruction({
	    amount: lamports,
            source: sender,
            destination: "2CKsECMaCbQFTLtT9iPC31NcrNrk5NMfB78yGBgQ4nYU",
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

function Unit({wallet, style, value: data}) {
    if (! data) {
	return <p>No unit</p>
    }

    let files = Object.entries(data.files)
    let [thumb, setThumb] = useState(null)

    if (! thumb && files.some(Boolean)) {
	setThumb(files[0][0])
    }

    let [selected, setSelected] = useContext(WalletContext)
    let wallets = useWallets()
    let chosen = wallets[0] // @todo user has to make this choice

    let transactionSendingSigner = useWalletAccountTransactionSendingSigner(chosen.accounts[0], "solana:devnet")

    async function pick(unit, accessType) {
	let txSignature = null
	if ("rent" == accessType) {
	    let rentForUnitResp = await fetch(`${API}/units/${unit}/rent`)
	    let rentForUnit = await rentForUnitResp.json()

	    // make the transaction
	    let txSignatureRaw = await transfer(transactionSendingSigner, rentForUnit.account, rentForUnit.lamports)
	    txSignature = bs58.encode(txSignatureRaw)
	}

	console.log(["SIGNATURE ", txSignature])
	await fetch(
	    `${API}/units/pick`,
	    {
		method: "POST",
		body: JSON.stringify({unit: unit, sig: txSignature}),
		headers: {"Content-type": "application/json"}
	    }
	)
    }

    return (
	<div className="picker"
	     style={{
		 display: "flex",
		 flexDirection: "column",
		 alignItems: "flex-end"
	     }}>
	    <div className="button unit" style={{padding: "1em",
						 display: "flex",
						 flexDirection: "column",
						 flexWrap: "wrap",
						 alignContent: "space-between",
						 justifyContent: "center"}}>
		<div>
		    <p>address: {data.address}</p>
		    <p>access: {data.access}</p>
		</div>
		<div style={{width: "72px",
			     height: "72px",
			     borderRadius: "100% 100%",
			     background: `url('${thumb}')`,
			     backgroundSize: "cover"}}></div>
	    </div>
	    <button className="button" onClick={function(e) { pick(data.address, data.access) }}>{data.access.toUpperCase()}</button>
	</div>
    )
}

export default function TheZone() {

    let session = useContext(AuthContext)
    let viewerRef = useRef(null)
    let [loading, setLoading] = useState(true)
    let [units, setUnits] = useState({})
    let [visible, setVisible] = useState({
	B: true,
	A: true,
	MENU: false,
	RATE: false
    })
    
    function toggle(target) {
	setVisible({...visible, [target]: !visible[target]})
    }

    async function fetchUnits() {
	let resp = await fetch(`${API}/units`)
	setUnits(await resp.json())
    }

    useEffect(function () {
	if (session) {
	    setLoading(false)
	}
    }, [session])

    useEffect(function () {
	if (! units.picked) {
	    fetchUnits()
	}
    }, [])
    
    if (loading) {
	return <div>Loading...</div>
    }
    
    if (! session) {
        return <Navigate to={{ pathname: "/" }} />
    }

    if (! units.picked) {
	return (
	    <>
		<p>Studyunit picker!</p>
		<div style={{display: "flex"}}>
		    {Object.entries(units)
		     .filter(function([k, v]) {
			 return ["rent", "free"].includes(k)
		     })
		     .map(function([k, v]) {
			 return <Unit value={v} />
		     })}
		</div>
	    </>
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
			 <Viewer id="focusedB" dashes={style.color.mentor} unit={units.picked} width="500" height="500" />
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
		     
		     <div style={{display: "flex"}}>
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
