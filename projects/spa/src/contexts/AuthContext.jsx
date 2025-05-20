import { createContext, useContext, useEffect, useState } from "react"
import { API } from "../utils/api"
import { Navigate } from "react-router-dom"

let AuthContext = createContext(null)

async function authentication() {
    let result = await fetch(
        `${API}/authn/session`,
        {
            method: "GET",
	    mode: "cors", // dev-only
	    credentials: "include",
        }
    )

    if (! result.ok && window.location.hash != "") {
	window.location.replace("/")
    }
    
    return await result.json()
}

function AuthProvider({children}) {
    let [session, setSession] = useState(null)

    useEffect(function() {
	authentication().then(setSession)
    }, [])
    
    return (
	<AuthContext.Provider value={session}>
	    {children}
	</AuthContext.Provider>
    )
}

export { AuthContext, AuthProvider }
