import { createContext, useContext, useEffect, useRef, useState } from "react"
import Canvas from "../../components/Canvas"
import style from "../../utils/style"

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
	<div style={{position: "fixed",
		     top: 0,
		     left: 0,
		     width: "80%",
		     height: "100%",
		     background: style.color.menus}}>
	    <nav>
		<ul>
		    <li style={{listStyleType: "none", padding: "7px"}}>
			<button className="button" onClick={function() {toggle("MENU")}}>THE ZONE</button>
		    </li>
		    {[
			"SALES",
			"HELP & FAQ",
			"SETINGS"
		    ].map(function(e){
			return (
			    <li key={e} style={{listStyleType: "none", padding: "7px"}}>
				<button className="button">{e}</button>
			    </li>
			)
		    })}
		</ul>
	    </nav>
	</div>
    )
}

export default function TheZone() {

    let [visible, setVisible] = useState({
	B: true,
	A: true,
	MENU: false
    })

    function toggle(target) {
	setVisible({...visible, [target]: !visible[target]})
    }

    return (
        <VisibleContext.Provider value={{visible, setVisible}}>
	    {visible.MENU &&
	     <Menu />}
            <div className="thezone" style={{textTransform:"uppercase"}}>
		<h2>Welcome to The Zone!</h2>
		<p>THIS HERE IS THE CENTRAL POINT OF THE ENTIRE APPLICATION. NO MATTER WHAT YOU DO YOU ENTER THE ZONE AND EVERYTHING SHOULD BE READY FOR YOU</p>
		<button className="button" style={{background: style.color.mentor}} onClick={function(){toggle("B")}}>TOGGLE SIDE B</button>
		<button className="button" style={{background: style.color.student}} onClick={function(){toggle("A")}}>TOGGLE SIDE A</button>
		<button className="button" onClick={function(){toggle("MENU")}}>MENU</button>

		<div style={{display: "flex", flexWrap: "wrap"}}>
		    {visible.B &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Canvas id="focusedB" dashes={style.color.mentor} width="500" height="500" />
		     </section>}
		    
		    {visible.A &&
		     <section className="container" style={{flexGrow: 1}}>
			 <Canvas id="focusedA" dashes={style.color.student} width="500" height="500" />
		     </section>}
		</div>
	    </div>
        </VisibleContext.Provider>
    )
}
