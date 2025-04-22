import { useEffect } from "react"
import OpenSeadragon from "openseadragon"

export default function Viewer(props) {
    useEffect(function() {
        let viewer = OpenSeadragon({
            id: "viewer",
            tileSources: {
                type: "image",
                "url": "https://openseadragon.github.io//example-images/grand-canyon-landscape-overlooking.jpg"
            }
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
