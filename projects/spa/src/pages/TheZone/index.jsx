import { createContext, useContext, useEffect, useRef, useState } from "react"
import { AuthContext } from "../../contexts/AuthContext"
import Canvas from "../../components/Canvas"
import Viewer from "../../components/Viewer"
import { API } from "../../utils/api"
import style from "../../utils/style"
import { Navigate } from "react-router-dom"

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

function Unit({style, value: data}) {
    if (! data) {
	return <p>No unit</p>
    }

    let files = Object.entries(data.files)
    let [thumb, setThumb] = useState(null)

    if (! thumb && files.some(Boolean)) {
	setThumb(files[0][0])
    }

    async function pick(unit) {
	await fetch(`${API}/units/pick`, {method: "POST", body: JSON.stringify({unit: unit}), headers: {"Content-type": "application/json"}})
    }

    return (
	<div style={{display: "flex",
		     flexDirection: "column",
		     alignItems: "flex-end"}}>
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
	    <button className="button" onClick={function(e) { pick(data.address) }}>{data.access.toUpperCase()}</button>
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
	MENU: false
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
		</div>
		
		<div style={{display: "flex", flexWrap: "wrap"}}>
		    {visible.B &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Viewer id="focusedB" dashes={style.color.mentor} unit={units.picked} width="500" height="500" />
		     </section>}
		    
		    {visible.A &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Canvas id="focusedA" dashes={style.color.student} width="500" height="500" />
		     </section>}
		</div>
	    </VisibleContext.Provider>
	</div>
    )
}
