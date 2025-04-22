import { useContext, useEffect, useState } from "react"
import style from "../../utils/style"
import { AuthContext } from "../../contexts/AuthContext"
import { WalletContext } from "../../contexts/WalletContext"
import { useWallets, useConnect, useDisconnect } from "@wallet-standard/react-core"

function Star() {

    return (
	<>
            <svg width="219"
		 xmlns="http://www.w3.org/2000/svg"
		 height="216"
		 id="screenshot-e384008e-ccbd-80a0-8006-05ea9f514786"
		 viewBox="-161 -1591 219 216"
		 style={{display: "block", WebkitPrintColorAdjust: "exact"}}
		 xmlnsXlink="http://www.w3.org/1999/xlink"
		 fill="none"
		 version="1.1">
                <style>
                </style>
                <g id="shape-e384008e-ccbd-80a0-8006-05ea9f514786" style={{fill:"#000000"}} filter="url(#filter-render-286)" width="160" height="160" rx="0" ry="0">
                    <defs>
			<filter id="filter-render-286" x="-0.09202453987730061" y="-0.09375" width="1.2576687116564418" height="1.2625" filterUnits="objectBoundingBox" colorInterpolationFilters="sRGB">
			    <feFlood floodOpacity="0" result="BackgroundImageFix">
			    </feFlood>
			    <feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0">
			    </feColorMatrix>
			    <feOffset dx="4" dy="4">
			    </feOffset>
			    <feGaussianBlur stdDeviation="0">
			    </feGaussianBlur>
			    <feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0">
			    </feColorMatrix>
			    <feBlend mode="normal" in2="BackgroundImageFix" result="filter_e384008e-ccbd-80a0-8006-05eac53f6b70">
			    </feBlend>
			    <feBlend mode="normal" in="SourceGraphic" in2="filter_e384008e-ccbd-80a0-8006-05eac53f6b70" result="shape">
			    </feBlend>
			</filter>
			<filter id="filter-shadow-render-286" x="-0.09202453987730061" y="-0.09375" width="1.2576687116564418" height="1.2625" filterUnits="objectBoundingBox" colorInterpolationFilters="sRGB">
			    <feFlood floodOpacity="0" result="BackgroundImageFix">
			    </feFlood>
			    <feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0">
			    </feColorMatrix>
			    <feOffset dx="4" dy="4">
			    </feOffset>
			    <feGaussianBlur stdDeviation="0">
			    </feGaussianBlur>
			    <feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0">
			    </feColorMatrix>
			    <feBlend mode="normal" in2="BackgroundImageFix" result="filter_e384008e-ccbd-80a0-8006-05eac53f6b70">
			    </feBlend>
			    <feBlend mode="normal" in="SourceGraphic" in2="filter_e384008e-ccbd-80a0-8006-05eac53f6b70" result="shape">
			    </feBlend>
			</filter>
                    </defs>
                    <g id="shape-e384008e-ccbd-80a0-8006-05ea9f57d81d" style={{display:"none"}}>
			<g className="fills" id="fills-e384008e-ccbd-80a0-8006-05ea9f57d81d">
			    <rect rx="0" ry="0" x="-145" y="-1575" transform="matrix(1.000000, 0.000000, 0.000000, 1.000000, 0.000000, 0.000000)" width="160" height="160" fill="none" style={{fill:"none"}}>
			    </rect>
			</g>
                    </g>
                    <g id="shape-e384008e-ccbd-80a0-8006-05ea9f5b68cc">
			<g className="fills" id="fills-e384008e-ccbd-80a0-8006-05ea9f5b68cc">
			    <path d="M-65.000,-1575.000L-46.459,-1552.063L-17.977,-1559.721L-16.459,-1530.267L11.085,-1519.721L-5.000,-1495.000L11.085,-1470.279L-16.459,-1459.733L-17.977,-1430.279L-46.459,-1437.937L-65.000,-1415.000L-83.541,-1437.937L-112.023,-1430.279L-113.541,-1459.733L-141.085,-1470.279L-125.000,-1495.000L-141.085,-1519.721L-113.541,-1530.267L-112.023,-1559.721L-83.541,-1552.063L-65.000,-1575.000Z" style={{fill:"#feef00"}}>
			    </path>
			</g>
                    </g>
                    <g id="shape-e384008e-ccbd-80a0-8006-05eb06010ff6">
			<g transform="matrix(1.000000, 0.000000, 0.000000, 1.000000, 0.000000, 0.000000)" className="text-container" x="-145" y="-1535" width="163" height="91.99999999999955" rx="0" ry="0">
			    <defs>
				<pattern patternUnits="userSpaceOnUse" x="-145" y="-1535" width="72" height="79.1875" id="fill-0-render-289-0">
				    <g>
					<rect width="72" height="79.1875" style={{fill:"#000000",fillOpacity:"1"}}>
					</rect>
				    </g>
				</pattern>
				<pattern patternUnits="userSpaceOnUse" x="-145" y="-1535" width="72" height="79.1875" id="fill-1-render-289-0">
				    <g>
					<rect width="72" height="79.1875" style={{fill:"#000000",fillOpacity:"1"}}>
					</rect>
				    </g>
				</pattern>
			    </defs>
			    <g className="fills" id="fills-e384008e-ccbd-80a0-8006-05eb06010ff6">
				<text x="-99.5" y="-1496" dominantBaseline="ideographic" textLength="72" lengthAdjust="spacingAndGlyphs" style={{textTransform:"uppercase",fontFamily:"Ubuntu",letterSpacing:"normal",fontStyle:"normal",fontWeight:700,whiteSpace:"pre",fontSize:"36px",textDecoration:"none solid rgb(0, 0, 0)",direction:"ltr",fill:"#000000",fillOopacity:1}}>join</text>
			    </g>
			    <defs>
				<pattern patternUnits="userSpaceOnUse" x="-145" y="-1535" width="72" height="79.1875" id="fill-0-render-289-1">
				    <g>
					<rect width="72" height="79.1875" style={{fill:"#000000",fillOpacity:"1"}}>
					</rect>
				    </g>
				</pattern>
				<pattern patternUnits="userSpaceOnUse" x="-145" y="-1535" width="72" height="79.1875" id="fill-1-render-289-1">
				    <g>
					<rect width="72" height="79.1875" style={{fill:"#000000",fillOpacity:"1"}}>
					</rect>
				    </g>
				</pattern>
			    </defs>
			    <g className="fills" id="fills-e384008e-ccbd-80a0-8006-05eb06010ff6">
				<text x="-99.5" y="-1452.8125" dominantBaseline="ideographic" textLength="72" lengthAdjust="spacingAndGlyphs" style={{textTransform:"uppercase",fontFamily:"Ubuntu Mono",letterSpacing:"normal",fontStyle:"normal",fontWeight:700,whiteSpace:"pre",fontSize:"36px",textDecoration:"none solid rgb(0, 0, 0)",direction:"ltr",fill:"#000000",fillOopacity:1}}>now!</text>
			    </g>
			</g>
                    </g>
                </g>
            </svg>
	</>
    )
}

export default function Landing() {
    let [pane, setPane] = useState("mentor")

    useEffect(function() {}, [])

    let session = useContext(AuthContext)
    let [loading, setLoading] = useState(true)
    let [selected, setSelected] = useContext(WalletContext)
    let wallets = useWallets()
    let chosen = wallets[0] // @todo user has to make this choice

    // @todo move
    let [isConnecting, connect] = useConnect(chosen)
    let [isDisconnecting, disconnect] = useDisconnect(chosen)
    
    async function choose(uiwallet) {
	let connected = await connect()
	setSelected(connected[0]) // @todo user has to make this choice
    }

    function truncated(str, limit = 7) {
	if (!str) {
	    return str
	}
	
	let text = str?.toString().substring(0, limit)
	if (str.length > limit) {
	    return `${text}...`
	}

	return str
    }

    useEffect(function () {
        if (session) {
            setLoading(false)
        }
    }, [session])
                                    
    if (loading) {
        return <div>Loading...</div>
    }   

    return (
        <>
            <div className="landing" style={{textTransform:"uppercase"}}>
		<h1>welcome to [name-is-wip] <b>{session && truncated(session.address)}</b></h1>
		<h2>the place to be!</h2>
		<a onClick={function(e){
		       e.preventDefault()
		       if (!session.address) {
			   choose(chosen)
			   return
		       }
		       window.location.replace("/zone")
		   }} className="star-sign">
		    <Star />
		</a>

		<button className="button" style={{background: style.color.mentor}} onClick={function(){setPane("mentor")}}>TEACH TO EARN</button>
		<button className="button" style={{background: style.color.student}} onClick={function(){setPane("student")}}>PAY TO LEARN</button>
		<button className="button" onClick={function(){window.location.replace("/zone")}}>ENTER THE ZONE</button>

		{"mentor" == pane &&
		 <div className="button pane" style={{background: style.color.mentor}}>
		     <h2>YOUR FEEDBACK IS VALUABLE! GET PAID!</h2>
		     <h4>{`YOUR INSIGHTS CAN BE CRUCIAL TO SOMEONE'S LEARNING JOURNEY.

THIS PLATFORM'S MISSION IS TO PROVIDE A WAY!`}</h4>
		 </div>}

		{"student" == pane && 
		 <div id="mentor" className="button pane" style={{background: style.color.student}}>
		     <h2>LEARN TO DRAW WITH ALMOST NO EFFORT!</h2>
		     <h4>{`DON'T KNOW WHERE TO BEGIN?

THIS PLATFORM OFFERS ALGORITHMIC CURRICULUMS THAT ACT AS A GUARDRAIL FOR YOUR LEARNING.

THIS IS A VERY LOW BARRIER TO ENTRY AND A GREAT WAY TO EFFORTLESSLY INVEST IN YOUR SKILLS.

YOU'LL RECEIVE VALUABLE FEEDBACK FROM EXPERIENCED MENTORS TO HELP YOU IMPROVE.`}</h4>
		 </div>}
            </div>
        </>)
}
