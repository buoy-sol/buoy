import { useEffect } from "react"
import OpenSeadragon from "openseadragon"
import { API } from "../utils/api"

export default function Viewer(props) {
    useEffect(function() {
        let viewer = OpenSeadragon({
            id: "viewer",
            tileSources: {
                type: "image",
		"url": `${API}/units/${props.unit}.jpg`
                // "url": "https://openseadragon.github.io//example-images/grand-canyon-landscape-overlooking.jpg"
            },
	    showNavigationControl: false,
	    maxZoomPixelRatio: 3
        })
                                                                                                               
        return function() {
            viewer.destroy()
        }
    }, [])
                                                                                                               
    let style = {
        width: `${props.width}px`,
        height: `${props.height}px`,
        touchAction: "none",
        border: `2px dashed ${props.dashes || 'red'}`
                                                                                                               
    }
    return <div id="viewer" style={style}></div>
}
