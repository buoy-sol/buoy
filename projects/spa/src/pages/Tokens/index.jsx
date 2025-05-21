import { createContext, useContext, useEffect, useState } from "react"
import bs58 from "bs58"
import { getBase64EncodedWireTransaction, getTransactionDecoder, compileTransaction } from "@solana/kit"

import { useSignTransaction, useSignAndSendTransaction } from "@solana/react"
import { useConnect, useDisconnect, useWallets, getWalletAccountFeature } from "@wallet-standard/react-core"
// import { signTransaction } from "@solana/transactions" // NOT IN USE

import Cardteaser from "../../components/Cardteaser"
import { AuthContext } from "../../contexts/AuthContext"
import { WalletContext } from "../../contexts/WalletContext"
import { API } from "../../utils/api"
import style from "../../utils/style"

const VisibleContext = createContext({
    B: true,
    A: true,
    MENU: false
})
                                                                                                          
function Menu({style: styled}) {
    let {visible, setVisible} = useContext(VisibleContext)
                                                                                                          
    function toggle(target) {
        setVisible({...visible, [target]: !visible[target]})
    }
                                                                                                          
    return (
        <div id="menu"
             style={{...styled, display: "flex",
                     alignItems: "center",
                     justifyContent: "center",
                     top: 0,
                     left: 0,
                     height: "100%",
                     background: style.color.menus}}>
            <nav>
                <ul style={{padding: 0}}>
                    {[
			{href: "/#zone", text: "THE ZONE"},
                        {href: "/#tokens", text: "YOUR TOKENS"},
                        {href: "/#help", text: "HELP & FAQ"},
                        {href: "/#settings", text: "SETINGS"}
                    ].map(function(e){
                        return (
                            <li key={e.text} style={{listStyleType: "none"}}>
                                <button className="button"><a href={e.href}>{e.text}</a></button>
                            </li>
                        )
                    })}
                </ul>
            </nav>
        </div>
    )
}

export default function Tokens() {

    let transactionSendingSigner;
    let signAndSendTransaction;
    
    let [cards, setCards] = useState([])
    let [created, setCreated] = useState(null)
    let [files, setFiles] = useState([{raw: ""}])
    let [loading, setLoading] = useState(true)
    let [visible, setVisible] = useState({
	CREATOR: false,
	EDITOR: false,
	// etc
    })
    let [selected, setselected] = useContext(WalletContext)

    let session = useContext(AuthContext)
    
    let wallets = useWallets()
    let chosen = wallets[0] // @todo user has to make this choice
                                                                       
    // @todo move
    let [isConnecting, connect] = useConnect(chosen)
    let [isDisconnecting, disconnect] = useDisconnect(chosen)
          
    async function choose(uiwallet) {
        let connected = await connect()
        setSelected(connected[0]) // @todo user has to make this choice

	signTransaction = useSignTransaction(chosen.accounts[0], "solana:devnet")
	// let signer = useWalletAccountTransactionSigner(chosen.accounts[0], "solana:devnet")
	signAndSendTransaction = useSignAndSendTransaction(chosen.accounts[0], "solana:devnet")
    }
                                                                                            
    async function signAndSend(txBase64) {
	await choose(null)
	
        let txBytes = Uint8Array.from(atob(txBase64), function(c) {
            return c.charCodeAt(0)
        })
                                                                                               
        return await signAndSendTransaction({transaction: txBytes})
    }
    
    async function fetchCards() {
	let cardsResp = await fetch(`${API}/cards`, {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }})
	setCards(await cardsResp.json())
    }

    async function storeCard(formData) {
	let storedCardResp = await fetch(`${API}/cards`, {
	    method: "POST",
	    body: formData,
	    headers: {
		"Content-type": "application/json",
		"Authorization": `Bearer ${localStorage.getItem("bearer")}`
	    }
	})
	setCreated(await storedCardResp.json())
    }

    async function sign(txBase64) {
	let txBytes = Uint8Array.from(atob(txBase64), function(c) {
	    return c.charCodeAt(0)
	})

	let signature = await signTransaction({transaction: txBytes})
	let signedTx = String.fromCharCode.apply(null, signature.signedTransaction)
	let signedTxBase64 = btoa(signedTx)

	return signedTxBase64
    }

    async function escrowToken(cardIdentifier) {
	let txResp = await fetch(
	    `${API}/token/escrow/tx?card_id=${cardIdentifier}`,
            {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)

	let txData = await txResp.json()
	console.log(await signAndSend(txData.txn_escrow_to))
    }

    async function retrieveToken(cardIdentifier) {
	let txResp = await fetch(
	    `${API}/token/retrieval/tx?card_id=${cardIdentifier}`,
	    {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)

	let txData = await txResp.json()
	console.log(await signAndSend(txData.txn_retrieval))

	await fetch(
	    `${API}/token/retrieve/tx?card_id=${cardIdentifier}`,
	    {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)
    }
   
    async function mintToken(cardIdentifier) {
	let txResp
	let txBase64
	let txData

	if (! cardIdentifier) {
	    throw new Error(`Invalid card identifier ${cardIdentifier}!`)
	}
	
	// create mint account
	txResp = await fetch(
	    `${API}/token/account/mint/tx`,
	    {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)
	txData = await txResp.json()
	let mintAccount = txData.mint_account

	await sign(txData.txn)

	// create token account(s)
	txResp = await fetch(
	    `${API}/token/account/tx?mint_account=${mintAccount}`,
	    {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)
	txData = await txResp.json()
	let tokenAccount = txData.token_account

	await sign(txData.txn)
	await sign(txData.txn_escrows)
    
	// mint & freeze
	txResp = await fetch(
	    `${API}/token/mint/tx?mint_account=${mintAccount}&token_account=${tokenAccount}&card_id=${cardIdentifier}`,
	    {headers: {"Content-type": "application/json", "Authorization": `Bearer ${localStorage.getItem("bearer")}` }}
	)
	txData = await txResp.json()

	console.log(await sign(txData.txn_mint_to))
    }
    
    function mediaChange(e, idx) {
	e.preventDefault()
	if (! files[idx].raw) {
	    files.push({raw: ""})
	}
	
	try {
	    files[idx] = {raw: URL.createObjectURL(e.target.files[0]), filename: e.target.files[0].name}
	} catch (ex) {
	    files[idx] = {raw: ""}
	}

	setFiles([...files])
    }
    
    useEffect(function() {
	fetchCards()
    }, [])

    useEffect(function() {}, [created, files])

    useEffect(function () {
        if (session) {
            setLoading(false)
        }                        
    }, [session])

    if (loading) {
	return <p>Loading!</p>
    }
    
    return (
	<>
	    <div id="tokens"
		 style={{
		     width: "100%",
		     minWidth: "50vw",
		     display: "flex",
		     flexWrap: "nowrap"
		 }}>
		<Menu style={{width: "16%"}} />
		<div style={{width: "32%"}}>
		    {cards.some(Boolean) && cards.map(function(card) {
			let explorer = `https://explorer.solana.com/address/${card.address}?cluster=devnet`
			return (
			    <div key={card.address}>
				<Cardteaser style={{maxWidth: "0px"}} value={card} />
				{!card.spl &&
				 <button className="button"
					 onClick={function(e) {
					     mintToken(card.identifier)
					 }}>MINT TOKEN</button>
				}
				{card.spl &&
				 (
				     <>
					 {(0 < card.spl.data.amount) &&
					  <button className="button"
						  style={{cursor: "help", background: "lightgrey"}}
						  title="FOR RENTING"
						  onClick={function(e) {
						      escrowToken(card.identifier)
						  }}>ESCROW</button>
					 }
					 {(0 == card.spl.data.amount) &&
                                          <button className="button"
                                                  style={{cursor: "help", background: "lightgrey"}}
                                                  title="FROM RENTING"
                                                  onClick={function(e) {
                                                      retrieveToken(card.identifier)
                                                  }}>RETRIEVE</button>
                                         }
					 <button className="button"><a target="_blank" href={explorer}>see on chain &#x2197;</a></button>
				     </>
				 )
				}
				<p>-</p>
			    </div>
			)
		    })}
		    <div>
			{! cards.some(Boolean) &&
			 <div>
			     <p>NO CARDS!</p>
			 </div>
			}
			<button onClick={function(e) {setVisible({...visible, CREATOR: true})}}>MAKE ONE</button>
		    </div>
		</div>

		<div className="button" style={{width: "50%"}}>
		    {visible.CREATOR &&
		     <>
			 <h2>CARD CREATOR</h2>
			 <form style={{}} action={storeCard} encType="multipart/form-data">
			     {files.map(function(f, idx) {
				 return <input key={idx}
					       type="file"
					       name="media"
					       onChange={function(e) { mediaChange(e, idx) }} />
			     })}

			     {["media_front", "media_back"].map(function(selectionType) {
				 return (
				     <>
					 <label for={selectionType}><p>{selectionType}:</p></label>
					 {files.filter(function(f) {return f.raw}).map(function(f, idx){
					     return (
						 <div style={{
							  display: "flex",
							  alignItems: "center",
							  justifyContent: "space-evenly"
						      }}>
						     <img width="128px" src={f.raw} />
						     <input style={{
								margin: "1em",
							    }}
							    key={idx}
							    value={f.filename}
							    name={selectionType}
							    type="checkbox" />
						     <br />
						 </div>
					     )
					 })}
				     </>
				 )
			     })}

                             <label for="card_name"><p>card_name:</p></label>
                             <input id="card_mame" type="text" name="name" placeholder="Card name" />

			     <label for="for-rent">Rent</label>
			     <input id="for-rent" type="radio" name="access" value="rent" required />

			     <label for="for-free">Free</label>
			     <input id="for-free" type="radio" name="access" value="free" />

			     <input type="hidden" name="owner" value="" />
			     <input type="hidden" name="holder" value="" />
			     
			     <br />
			     <input type="submit" />
			 </form>
		     </>
		    }
		    {! Object.values(visible).some(Boolean) &&  <h2>CARD MANAGER</h2> }
		</div>
	    </div>
	</>
    )
}
