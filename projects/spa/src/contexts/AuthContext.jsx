import { createContext, useContext, useEffect, useState } from "react"
import { API } from "../utils/api"

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
    return await result.json()
}

function AuthProvider({children}) {
    let [session, setSession] = useState(null)

    useEffect(function(){    	
	setSession(authentication())
	console.log(session)
    }, [])
    
    return (
	<AuthContext.Provider value={null}>
	    {children}
	</AuthContext.Provider>
    )
}

export { AuthContext, AuthProvider }
