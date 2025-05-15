import { createContext, useContext, useEffect, useState } from "react"
import bs58 from "bs58"
import { getBase64EncodedWireTransaction, getTransactionDecoder, compileTransaction } from "@solana/kit"

import { useSignTransaction } from "@solana/react"
import { useWallets, getWalletAccountFeature } from "@wallet-standard/react-core"
import { signTransaction } from "@solana/transactions"

import Cardteaser from "../../components/Cardteaser"
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
                    <li style={{listStyleType: "none", padding: "7px"}}>
                        <button className="button" onClick={function() {toggle("MENU")}}>THE ZONE</button>
                    </li>
                    {[
                        "YOUR TOKENS",
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

export default function Tokens() {

    let [cards, setCards] = useState([])
    let [created, setCreated] = useState(null)
    let [files, setFiles] = useState([{raw: ""}])
    let [visible, setVisible] = useState({
	CREATOR: false,
	EDITOR: false,
	// etc
    })

    let wallets = useWallets()
    let chosen = wallets[0] // @todo user has to make this choice
    let signTransaction = useSignTransaction(chosen.accounts[0], "solana:devnet")
    // let signer = useWalletAccountTransactionSigner(chosen.accounts[0], "solana:devnet")

    async function fetchCards() {
	let cardsResp = await fetch(`${API}/cards`)
	setCards(await cardsResp.json())
    }

    async function storeCard(formData) {
	let storedCardResp = await fetch(`${API}/cards`, {
	    method: "POST",
	    credentials: "include",
	    body: formData
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

	return signature.SignedTransaction
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
	    {credentials: "include"}
	)
	txData = await txResp.json()
	let mintAccount = txData.mint_account

	await sign(txData.txn)

	// create token account
	txResp = await fetch(
	    `${API}/token/account/tx?mint_account=${mintAccount}`,
	    {credentials: "include"}
	)
	txData = await txResp.json()
	let tokenAccount = txData.token_account

	await sign(txData.txn)
    
	// mint & freeze
	txResp = await fetch(
	    `${API}/token/mint/tx?mint_account=${mintAccount}&token_account=${tokenAccount}&card_id=${cardIdentifier}`,
	    {credentials: "include"}
	)
	txData = await txResp.json()

	console.log(await sign(txData.txn))
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
			return (
			    <>
				{!card.spl &&
				 <button className="button" onClick={function(e) {
					     mintToken(card.identifier)
					 }}>MINT TOKEN</button>
				}
				<Cardteaser style={{maxWidth: "0px"}} value={card} />
			    </>
			)
		    })}
		    {! cards.some(Boolean) &&
		     <div>
			 <p>NO CARDS!</p>
			 <button onClick={function(e) {setVisible({...visible, CREATOR: true})}}>MAKE ONE</button>
		     </div>}
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

			     <input type="radio" name="access" value="rent" />
			     <input type="radio" name="access" value="free" />
			     <input type="hidden" name="contributor" value={chosen.accounts[0].address} />
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
