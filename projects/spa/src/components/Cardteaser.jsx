import { useContext, useEffect, useState } from "react"
import { API } from "../utils/api"

export default function Cardteaser({style, value: data}) {                                                                                                                                     
    
    return (
        <div className="picker"
             style={{
                 display: "flex",
                 flexDirection: "column",
                 alignItems: "flex-end",
             }}>
            <div className="button card" style={{...style, 
		     padding: "1em",
                     display: "flex",
                     flexDirection: "column",
                     flexWrap: "wrap",
                     alignContent: "space-between",
                     justifyContent: "center",
		     textOverflow: "ellipsis",
		     overflow: "hidden"
		 }}>
                <div>
		    <p>- address: {data.address}</p>
		    <p>- access: {data.access}</p>

		    {data.spl &&
		     <span>- minter: {data.spl.data.minter}</span>
		    }
		</div>
                <div style={{width: "72px",
                             height: "72px",
                             borderRadius: "100% 100%",
                             background: `url('${API}/cards/${data.identifier}')`,
                             backgroundSize: "cover"}}></div>
            </div>
        </div>
    )
}
